using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// An <see cref="ITenantKeyRegistry"/> that holds tenant key records in memory. It needs no database,
/// which suits tests and static (for example single-tenant) deployments where the key catalogue is
/// known at startup. It stores only metadata — TmkIds, versions and provider references — never key
/// material; the actual wrap/unwrap is an <see cref="IKeyProvider"/>'s job. The instance is immutable
/// and thread-safe.
/// </summary>
public sealed class InMemoryTenantKeyRegistry : ITenantKeyRegistry
{
    private readonly IReadOnlyDictionary<TenantId, TenantKeyRecord> _records;

    /// <summary>Creates a registry from a set of records, one per tenant.</summary>
    /// <exception cref="ArgumentNullException">The records, or any record, are null.</exception>
    /// <exception cref="ArgumentException">Two records are given for the same tenant.</exception>
    public InMemoryTenantKeyRegistry(IEnumerable<TenantKeyRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);

        var byTenant = new Dictionary<TenantId, TenantKeyRecord>();
        foreach (var record in records)
        {
            ArgumentNullException.ThrowIfNull(record, nameof(records));
            if (!byTenant.TryAdd(record.Tenant, record))
            {
                throw new ArgumentException($"More than one key record was provided for tenant '{record.Tenant}'.", nameof(records));
            }
        }

        _records = byTenant;
    }

    /// <inheritdoc />
    public TenantKeyRecord GetRecord(TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        if (_records.TryGetValue(tenant, out var record))
        {
            return record;
        }

        throw new KeyResolutionException($"No key record is registered for tenant '{tenant}'.");
    }
}
