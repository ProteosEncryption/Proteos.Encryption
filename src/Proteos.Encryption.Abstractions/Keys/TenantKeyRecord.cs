using System.Diagnostics.CodeAnalysis;

namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The neutral key catalogue of a tenant: a stable tenant master key id (TmkId) plus every key
/// version (each with its provider reference) and the current version. It is the model a
/// registry-backed or KMS-backed key provider resolves a tenant to; it carries no secret material
/// and forces no database — a registry can be in-memory, a file, or a table.
/// </summary>
/// <remarks>
/// The envelope key id stays <c>TmkId(16) ‖ Version(2, big-endian)</c> = 18 bytes, exactly as
/// before. Unlike the development provider (which derives a per-version id), the TmkId here is
/// stable across versions — the model the architecture specifies for production. <see cref="GetKnownKeyIds"/>
/// is what makes rotation-aware search (Step 18) work for KMS providers.
/// </remarks>
public sealed class TenantKeyRecord
{
    private const int TmkIdLength = 16;
    private const int VersionLength = 2;
    private const int KeyIdLength = TmkIdLength + VersionLength;

    private readonly byte[] _tmkIdBytes;
    private readonly IReadOnlyDictionary<ushort, TenantKeyVersion> _versionsByNumber;

    /// <summary>Creates a validated key record.</summary>
    /// <exception cref="ArgumentNullException">The tenant or versions are null, or a version is null.</exception>
    /// <exception cref="ArgumentException">The TmkId is empty, no versions are given, or a version number is duplicated.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The current version is not among the versions.</exception>
    public TenantKeyRecord(TenantId tenant, Guid tenantMasterKeyId, IReadOnlyCollection<TenantKeyVersion> versions, ushort currentVersion)
    {
        Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
        ArgumentNullException.ThrowIfNull(versions);

        if (tenantMasterKeyId == Guid.Empty)
        {
            throw new ArgumentException("Tenant master key id must not be empty.", nameof(tenantMasterKeyId));
        }

        var byNumber = new Dictionary<ushort, TenantKeyVersion>();
        foreach (var version in versions)
        {
            ArgumentNullException.ThrowIfNull(version, nameof(versions));
            if (!byNumber.TryAdd(version.Version, version))
            {
                throw new ArgumentException($"Key version {version.Version} is provided more than once.", nameof(versions));
            }
        }

        if (byNumber.Count == 0)
        {
            throw new ArgumentException("At least one key version is required.", nameof(versions));
        }

        if (!byNumber.ContainsKey(currentVersion))
        {
            throw new ArgumentOutOfRangeException(nameof(currentVersion), currentVersion, "The current version is not among the provided versions.");
        }

        TenantMasterKeyId = tenantMasterKeyId;
        CurrentVersion = currentVersion;
        _tmkIdBytes = tenantMasterKeyId.ToByteArray();
        _versionsByNumber = byNumber;
        Versions = byNumber.Values.OrderBy(version => version.Version).ToArray();
    }

    /// <summary>The tenant this record belongs to.</summary>
    public TenantId Tenant { get; }

    /// <summary>The stable 16-byte tenant master key id (the TmkId segment of every key id).</summary>
    public Guid TenantMasterKeyId { get; }

    /// <summary>All key versions, ascending by version number.</summary>
    public IReadOnlyList<TenantKeyVersion> Versions { get; }

    /// <summary>The version stamped on new data.</summary>
    public ushort CurrentVersion { get; }

    /// <summary>The key id for new data: <c>TmkId ‖ CurrentVersion</c>.</summary>
    public KeyId CurrentKeyId => BuildKeyId(CurrentVersion);

    /// <summary>The key id of a given version. Used by the provider to stamp and resolve data.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The version is not part of this record.</exception>
    public KeyId KeyIdFor(ushort version)
    {
        if (!_versionsByNumber.ContainsKey(version))
        {
            throw new ArgumentOutOfRangeException(nameof(version), version, "The version is not part of this key record.");
        }

        return BuildKeyId(version);
    }

    /// <summary>Every known key id (one per version) — the set rotation-aware search derives index terms for.</summary>
    public IReadOnlyCollection<KeyId> GetKnownKeyIds() => Versions.Select(version => BuildKeyId(version.Version)).ToArray();

    /// <summary>
    /// Resolves a key id (as stored in an envelope) back to its version of this record. Returns false
    /// when the id has the wrong length, a different TmkId, or an unknown version.
    /// </summary>
    public bool TryGetVersion(KeyId keyId, [NotNullWhen(true)] out TenantKeyVersion? version)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        version = null;
        var bytes = keyId.Span;
        if (bytes.Length != KeyIdLength || !bytes[..TmkIdLength].SequenceEqual(_tmkIdBytes))
        {
            return false;
        }

        var number = (ushort)((bytes[TmkIdLength] << 8) | bytes[TmkIdLength + 1]);
        return _versionsByNumber.TryGetValue(number, out version);
    }

    private KeyId BuildKeyId(ushort version)
    {
        var bytes = new byte[KeyIdLength];
        _tmkIdBytes.CopyTo(bytes, 0);
        bytes[TmkIdLength] = (byte)(version >> 8);
        bytes[TmkIdLength + 1] = (byte)version;
        return KeyId.FromBytes(bytes);
    }
}
