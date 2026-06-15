using System.Security.Cryptography;
using System.Text;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// A development-only <see cref="IKeyMaterialProvider"/> that derives all key material
/// deterministically from one or more versioned root keys. It needs no KMS, no database and no
/// files, which makes it convenient for development and tests — and unfit for production: anyone
/// with a root key can reproduce every key. Use a real KMS-backed provider in production.
/// </summary>
/// <remarks>
/// <para>
/// Derivation mirrors the documented hierarchy: a per-tenant master key
/// <c>HKDF(rootKey, tenant)</c>, then a per-purpose, per-scope subkey
/// <c>HKDF(masterKey, purpose || entity || property)</c>. Each rotation version has its own root
/// key, so different versions yield independent key material.
/// </para>
/// <para>
/// Key rotation: the provider holds every version's root key and a <see cref="CurrentVersion"/>.
/// New data is stamped with the current version's key id (<see cref="GetCurrentKeyId"/>); decryption
/// resolves whichever version is named in the envelope's key id (<see cref="DeriveKey"/>), so data
/// written under an older version stays readable. The version is carried in the last two bytes of
/// the key id (<c>masterKeyId(16) ‖ version(2, big-endian)</c>); resolution is generic with no
/// per-version special cases. A single-root-key provider is exactly version 1, byte-for-byte
/// compatible with data written before rotation existed.
/// </para>
/// <para>The instance is immutable and thread-safe; root keys are copied and never exposed, and no secret is logged.</para>
/// </remarks>
public sealed class LocalDevelopmentKeyProvider : IKeyMaterialProvider
{
    /// <summary>Minimum root key length in bytes (256-bit).</summary>
    public const int RootKeyMinLength = 32;

    /// <summary>Length in bytes of the derived symmetric keys (256-bit).</summary>
    public const int DerivedKeyLength = 32;

    private const int MasterKeyLength = 32;
    private const int TenantKeyIdLength = 16;
    private const int VersionLength = 2;
    private const int KeyIdLength = TenantKeyIdLength + VersionLength;
    private const ushort InitialVersion = 1;

    private const string MasterKeyIdLabel = "proteos.local-dev.tmk-id.v1";
    private const string MasterKeyLabel = "proteos.local-dev.tmk.v1";

    private static readonly byte[] DefaultDevelopmentRootKey =
        Encoding.ASCII.GetBytes("PROTEOS_LOCAL_DEVELOPMENT_INSECURE_ROOT_KEY");

    private readonly IReadOnlyDictionary<ushort, byte[]> _rootKeysByVersion;
    private readonly ushort _currentVersion;

    /// <summary>Creates a single-version provider (version 1) with an explicit root key. The key is copied.</summary>
    /// <exception cref="ArgumentException">The root key is shorter than <see cref="RootKeyMinLength"/>.</exception>
    public LocalDevelopmentKeyProvider(ReadOnlySpan<byte> rootKey)
    {
        if (rootKey.Length < RootKeyMinLength)
        {
            throw new ArgumentException($"Development root key must be at least {RootKeyMinLength} bytes.", nameof(rootKey));
        }

        _rootKeysByVersion = new Dictionary<ushort, byte[]> { [InitialVersion] = rootKey.ToArray() };
        _currentVersion = InitialVersion;
    }

    private LocalDevelopmentKeyProvider(IReadOnlyDictionary<ushort, byte[]> rootKeysByVersion, ushort currentVersion)
    {
        _rootKeysByVersion = rootKeysByVersion;
        _currentVersion = currentVersion;
    }

    /// <summary>
    /// Creates a provider with a fixed, well-known, <b>insecure</b> development root key. Convenient
    /// for zero-configuration development; never use this in production.
    /// </summary>
    public static LocalDevelopmentKeyProvider CreateWithDefaultDevelopmentRootKey() => new(DefaultDevelopmentRootKey);

    /// <summary>
    /// Creates a rotating provider from several versioned root keys and the current version. New data
    /// uses <paramref name="currentVersion"/>; data written under any provided version stays decryptable.
    /// </summary>
    /// <exception cref="ArgumentNullException">The versions are null.</exception>
    /// <exception cref="ArgumentException">No versions are given, a version is duplicated, or the current version is not among them.</exception>
    public static LocalDevelopmentKeyProvider CreateRotating(IEnumerable<LocalDevelopmentKeyVersion> versions, ushort currentVersion)
    {
        ArgumentNullException.ThrowIfNull(versions);

        var rootKeysByVersion = new Dictionary<ushort, byte[]>();
        foreach (var version in versions)
        {
            ArgumentNullException.ThrowIfNull(version);
            if (!rootKeysByVersion.TryAdd(version.Version, version.RootKey))
            {
                throw new ArgumentException($"Key version {version.Version} is provided more than once.", nameof(versions));
            }
        }

        if (rootKeysByVersion.Count == 0)
        {
            throw new ArgumentException("At least one key version is required.", nameof(versions));
        }

        if (!rootKeysByVersion.ContainsKey(currentVersion))
        {
            throw new ArgumentException($"Current key version {currentVersion} is not among the provided versions.", nameof(currentVersion));
        }

        return new LocalDevelopmentKeyProvider(rootKeysByVersion, currentVersion);
    }

    /// <inheritdoc />
    public string ProviderId => "local-development-insecure";

    /// <summary>The version stamped on new data.</summary>
    public ushort CurrentVersion => _currentVersion;

    /// <summary>All versions this provider can resolve (decrypt), ascending. Old versions are never dropped.</summary>
    public IReadOnlyCollection<ushort> KnownVersions => _rootKeysByVersion.Keys.OrderBy(version => version).ToArray();

    /// <inheritdoc />
    public KeyId GetCurrentKeyId(TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        return BuildKeyId(_rootKeysByVersion[_currentVersion], tenant, _currentVersion);
    }

    /// <inheritdoc />
    public IReadOnlyCollection<KeyId> GetKnownKeyIds(TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        return _rootKeysByVersion
            .OrderBy(pair => pair.Key)
            .Select(pair => BuildKeyId(pair.Value, tenant, pair.Key))
            .ToArray();
    }

    /// <inheritdoc />
    public byte[] DeriveKey(TenantId tenant, KeyDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentNullException.ThrowIfNull(descriptor);

        var rootKey = ResolveRootKey(tenant, descriptor.KeyId);

        var masterKey = Hkdf.DeriveKey(rootKey, SubkeyDerivation.BuildInfo(MasterKeyLabel, tenant.Value), MasterKeyLength);
        try
        {
            return SubkeyDerivation.DeriveSubkey(masterKey, descriptor.Purpose, descriptor.Scope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    private byte[] ResolveRootKey(TenantId tenant, KeyId keyId)
    {
        var bytes = keyId.Span;
        if (bytes.Length != KeyIdLength)
        {
            throw new KeyResolutionException($"Key id {keyId} is not a Local Development key id.");
        }

        var version = (ushort)((bytes[TenantKeyIdLength] << 8) | bytes[TenantKeyIdLength + 1]);
        if (!_rootKeysByVersion.TryGetValue(version, out var rootKey))
        {
            throw new KeyResolutionException($"Key id {keyId} refers to unknown key version {version}.");
        }

        // The version selects the root key; verifying the master-key-id prefix confirms the key id
        // belongs to this tenant under that version (and rejects foreign or tampered ids).
        if (!keyId.Equals(BuildKeyId(rootKey, tenant, version)))
        {
            throw new KeyResolutionException($"Key id {keyId} does not belong to the tenant.");
        }

        return rootKey;
    }

    private static KeyId BuildKeyId(byte[] rootKey, TenantId tenant, ushort version)
    {
        // The master key id is a public identifier, derived with a label distinct from the master key
        // itself, so publishing it reveals nothing about the key.
        var masterKeyId = Hkdf.DeriveKey(rootKey, SubkeyDerivation.BuildInfo(MasterKeyIdLabel, tenant.Value), TenantKeyIdLength);

        var keyIdBytes = new byte[KeyIdLength];
        masterKeyId.CopyTo(keyIdBytes, 0);
        keyIdBytes[TenantKeyIdLength] = (byte)(version >> 8);
        keyIdBytes[TenantKeyIdLength + 1] = (byte)version;

        return KeyId.FromBytes(keyIdBytes);
    }
}
