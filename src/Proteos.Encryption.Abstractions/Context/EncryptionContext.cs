namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The runtime context required to encrypt or decrypt a single field value: the tenant (which
/// selects the master key) together with the logical scope (which is bound into key
/// derivation). It deliberately carries no key purpose — the operation determines it — so the
/// same context describes both the encryption and the blind-index path.
/// </summary>
public sealed record EncryptionContext
{
    /// <summary>The tenant that owns the value; selects the Tenant Master Key.</summary>
    public TenantId Tenant { get; }

    /// <summary>The logical entity/property scope of the value.</summary>
    public EncryptedDataScope Scope { get; }

    /// <summary>Creates an encryption context.</summary>
    /// <exception cref="ArgumentNullException">Tenant or scope is null.</exception>
    public EncryptionContext(TenantId tenant, EncryptedDataScope scope)
    {
        Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
    }
}
