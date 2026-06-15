namespace Proteos.Encryption.Abstractions;

/// <summary>
/// One version of a tenant master key: its version number (which appears in the envelope key id)
/// and the provider key reference that wraps it. Versions are how rotation is expressed — a new
/// version is added and becomes current, while older versions stay in the record so their data
/// remains decryptable.
/// </summary>
public sealed record TenantKeyVersion
{
    /// <summary>The version number (1, 2, 3, …); forms the version segment of the key id.</summary>
    public ushort Version { get; }

    /// <summary>The provider key (KEK) that wraps this version's tenant master key.</summary>
    public ProviderKeyReference KeyReference { get; }

    /// <summary>
    /// The KEK-wrapped tenant master key, when known. It is safe to store and back up — useless
    /// without KEK access — and is what a registry-backed provider unwraps to derive working keys.
    /// It is optional: a metadata-only record (for listing versions or building key ids) needs none,
    /// but deriving a key from a version requires it.
    /// </summary>
    public WrappedKey? WrappedTenantMasterKey { get; }

    /// <summary>Creates a tenant key version.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The version is 0 (versions start at 1).</exception>
    /// <exception cref="ArgumentNullException">The key reference is null.</exception>
    public TenantKeyVersion(ushort version, ProviderKeyReference keyReference, WrappedKey? wrappedTenantMasterKey = null)
    {
        if (version == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(version), version, "Key version must be 1 or greater.");
        }

        Version = version;
        KeyReference = keyReference ?? throw new ArgumentNullException(nameof(keyReference));
        WrappedTenantMasterKey = wrappedTenantMasterKey;
    }
}
