namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// The encrypted-property metadata of a single entity type: the type, its entity logical name and
/// the validated descriptors of its encrypted (and searchable) properties.
/// </summary>
public sealed class EncryptedEntityMetadata
{
    public EncryptedEntityMetadata(Type entityType, string? entityLogicalName, IReadOnlyList<EncryptedPropertyDescriptor> properties)
    {
        EntityType = entityType ?? throw new ArgumentNullException(nameof(entityType));
        EntityLogicalName = entityLogicalName;
        Properties = properties ?? throw new ArgumentNullException(nameof(properties));
    }

    /// <summary>The scanned entity type.</summary>
    public Type EntityType { get; }

    /// <summary>The entity logical name from <c>[EncryptedEntity]</c>; null when the entity has no encrypted properties.</summary>
    public string? EntityLogicalName { get; }

    /// <summary>The encrypted properties found on the entity (empty if none).</summary>
    public IReadOnlyList<EncryptedPropertyDescriptor> Properties { get; }

    /// <summary>Whether the entity has any encrypted property.</summary>
    public bool HasEncryptedProperties => Properties.Count > 0;
}
