namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The source of tenant key records: where a tenant's master key versions live. It is deliberately
/// storage-agnostic — an implementation may keep records in memory, in a file, or in a table — so
/// the key model does not force a database. A registry-backed key material provider resolves a
/// tenant through this seam, then uses the record's provider references and an <see cref="IKeyProvider"/>
/// to obtain working keys.
/// </summary>
public interface ITenantKeyRegistry
{
    /// <summary>Returns the key record for a tenant.</summary>
    /// <exception cref="ArgumentNullException">The tenant is null.</exception>
    /// <exception cref="ProteosEncryptionException">No record is registered for the tenant.</exception>
    TenantKeyRecord GetRecord(TenantId tenant);
}
