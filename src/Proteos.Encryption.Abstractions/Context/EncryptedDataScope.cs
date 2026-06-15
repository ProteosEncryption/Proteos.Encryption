namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The tenant-independent logical address of an encrypted field: which entity and which
/// property. It is bound into the key derivation so a value cannot be silently moved to a
/// different column and still decrypt.
/// </summary>
public sealed record EncryptedDataScope
{
    /// <summary>Stable logical name of the owning entity.</summary>
    public LogicalName Entity { get; }

    /// <summary>Stable logical name of the property.</summary>
    public LogicalName Property { get; }

    /// <summary>Creates a scope from an entity and property logical name.</summary>
    /// <exception cref="ArgumentNullException">Either name is null.</exception>
    public EncryptedDataScope(LogicalName entity, LogicalName property)
    {
        Entity = entity ?? throw new ArgumentNullException(nameof(entity));
        Property = property ?? throw new ArgumentNullException(nameof(property));
    }

    public override string ToString() => $"{Entity.Value}.{Property.Value}";
}
