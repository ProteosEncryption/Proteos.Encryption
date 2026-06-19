namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Resolves the symmetric key material the encryption layer uses for a tenant and a specific
/// key descriptor (key id, purpose, scope). Implementations differ in how the material is
/// sourced — deterministic derivation for development, a KMS-backed master key plus derivation
/// in production — but all enforce the same tenant-and-scope separation.
/// </summary>
/// <remarks>
/// This is the higher-level seam the encryption service depends on. It is distinct from
/// <see cref="IKeyProvider"/>, which is the low-level KEK wrap/unwrap seam a KMS adapter
/// implements; a production key-material provider would use an <see cref="IKeyProvider"/>
/// internally to obtain the tenant master key, then derive subkeys from it.
/// </remarks>
public interface IKeyMaterialProvider
{
    /// <summary>Stable identifier of this provider, for diagnostics. Never contains secret material.</summary>
    string ProviderId { get; }

    /// <summary>Returns the key id to stamp on new data for a tenant (the tenant's current master key identity).</summary>
    /// <exception cref="ArgumentNullException">The tenant is null.</exception>
    KeyId GetCurrentKeyId(TenantId tenant);

    /// <summary>
    /// Derives the symmetric key for a tenant and descriptor. The returned array is secret key
    /// material owned by the caller, who is responsible for clearing it.
    /// </summary>
    /// <exception cref="ArgumentNullException">Tenant or descriptor is null.</exception>
    /// <exception cref="KeyResolutionException">The descriptor's key id does not belong to the tenant.</exception>
    byte[] DeriveKey(TenantId tenant, KeyDescriptor descriptor);

    /// <summary>
    /// Returns every key id whose data a tenant may still hold — the current id plus any rotated-out
    /// versions that are still resolvable. Rotation-aware search derives one index term per returned
    /// id, so data written under any version stays findable. The ids are opaque, so the caller needs
    /// no knowledge of versions or of the concrete provider. The default returns only the current id
    /// (no rotation); a rotating provider overrides it.
    /// </summary>
    /// <exception cref="ArgumentNullException">The tenant is null.</exception>
    IReadOnlyCollection<KeyId> GetKnownKeyIds(TenantId tenant) => [GetCurrentKeyId(tenant)];
}
