using System.Security.Cryptography;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// A production-shaped <see cref="IKeyMaterialProvider"/> that derives working keys from a tenant key
/// catalogue. It keeps the two key layers cleanly separated: an <see cref="ITenantKeyRegistry"/>
/// supplies the tenant's <see cref="TenantKeyRecord"/> (TmkId, versions, current), an
/// <see cref="IKeyProvider"/> (the KEK seam, one per <see cref="KeyProviderKind"/>) unwraps the
/// tenant master key, and the canonical HKDF derivation produces the AES/HMAC working key. A future
/// Azure/AWS/Google integration is therefore only an <see cref="IKeyProvider"/> adapter — this class
/// stays vendor- and framework-free.
/// </summary>
/// <remarks>
/// The unwrapped tenant master key is zeroed right after the working key is derived; it is never
/// cached. <see cref="DeriveKey"/> bridges the synchronous derivation seam to the asynchronous KEK
/// seam by blocking — acceptable for a non-cached foundation; a production deployment would cache
/// unwrapped master keys to avoid a KMS round trip per call.
/// </remarks>
public sealed class RegistryKeyMaterialProvider : IKeyMaterialProvider
{
    private readonly ITenantKeyRegistry _registry;
    private readonly IReadOnlyDictionary<KeyProviderKind, IKeyProvider> _keyProviders;

    /// <summary>Creates a provider that routes to one or more KEK providers by <see cref="KeyProviderKind"/>.</summary>
    /// <exception cref="ArgumentNullException">The registry, the map, or a mapped provider is null.</exception>
    /// <exception cref="ArgumentException">No key providers are given.</exception>
    public RegistryKeyMaterialProvider(ITenantKeyRegistry registry, IReadOnlyDictionary<KeyProviderKind, IKeyProvider> keyProviders)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        ArgumentNullException.ThrowIfNull(keyProviders);

        if (keyProviders.Count == 0)
        {
            throw new ArgumentException("At least one key provider is required.", nameof(keyProviders));
        }

        var copy = new Dictionary<KeyProviderKind, IKeyProvider>(keyProviders.Count);
        foreach (var (kind, keyProvider) in keyProviders)
        {
            copy[kind] = keyProvider ?? throw new ArgumentNullException(nameof(keyProviders), $"The key provider for '{kind}' is null.");
        }

        _keyProviders = copy;
    }

    /// <summary>Creates a provider backed by a single KEK provider for one provider kind.</summary>
    public RegistryKeyMaterialProvider(ITenantKeyRegistry registry, KeyProviderKind providerKind, IKeyProvider keyProvider)
        : this(registry, new Dictionary<KeyProviderKind, IKeyProvider> { [providerKind] = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider)) })
    {
    }

    /// <inheritdoc />
    public string ProviderId => "registry";

    /// <inheritdoc />
    public KeyId GetCurrentKeyId(TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        return _registry.GetRecord(tenant).CurrentKeyId;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<KeyId> GetKnownKeyIds(TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        return _registry.GetRecord(tenant).GetKnownKeyIds();
    }

    /// <inheritdoc />
    public byte[] DeriveKey(TenantId tenant, KeyDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentNullException.ThrowIfNull(descriptor);

        var record = _registry.GetRecord(tenant);

        if (!record.TryGetVersion(descriptor.KeyId, out var version))
        {
            throw new KeyResolutionException($"Key id {descriptor.KeyId} does not belong to tenant '{tenant}'.");
        }

        if (version.WrappedTenantMasterKey is not { } wrappedMasterKey)
        {
            throw new KeyResolutionException($"Key id {descriptor.KeyId} has no wrapped tenant master key, so no working key can be derived.");
        }

        var keyProvider = ResolveKeyProvider(version.KeyReference);

        var masterKey = keyProvider.UnwrapAsync(wrappedMasterKey).AsTask().GetAwaiter().GetResult();
        try
        {
            return SubkeyDerivation.DeriveSubkey(masterKey, descriptor.Purpose, descriptor.Scope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    private IKeyProvider ResolveKeyProvider(ProviderKeyReference reference)
    {
        if (_keyProviders.TryGetValue(reference.Provider, out var keyProvider))
        {
            return keyProvider;
        }

        throw new KeyResolutionException($"No key provider is configured for provider kind '{reference.Provider}'.");
    }
}
