namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// The re-encryption plan for a single entity instance: which of its encrypted properties are stored
/// under an older key version and therefore need migrating to the current one. A later worker reads
/// this, re-encrypts each listed property and writes the row back. Producing the plan reads only
/// envelope headers, never plaintext.
/// </summary>
public sealed class EncryptedEntityMigrationPlan
{
    public EncryptedEntityMigrationPlan(Type entityType, IReadOnlyList<EncryptedPropertyMigrationDescriptor> propertiesToMigrate)
    {
        EntityType = entityType ?? throw new ArgumentNullException(nameof(entityType));
        PropertiesToMigrate = propertiesToMigrate ?? throw new ArgumentNullException(nameof(propertiesToMigrate));
    }

    /// <summary>The entity type the plan applies to.</summary>
    public Type EntityType { get; }

    /// <summary>The encrypted properties that are stored under an older key version.</summary>
    public IReadOnlyList<EncryptedPropertyMigrationDescriptor> PropertiesToMigrate { get; }

    /// <summary>True when at least one property needs migrating.</summary>
    public bool RequiresMigration => PropertiesToMigrate.Count > 0;
}
