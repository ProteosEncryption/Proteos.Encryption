namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Marks a property whose value is stored encrypted. <see cref="Name"/> is the property's stable
/// logical name; together with the entity logical name from <see cref="EncryptedEntityAttribute"/>
/// it forms the scope that is bound into key derivation. The logical names are given explicitly
/// and never derived from CLR names, so a rename does not break stored data.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public class EncryptedAttribute : Attribute
{
    public EncryptedAttribute()
    {
    }

    public EncryptedAttribute(string name)
    {
        Name = name;
    }

    /// <summary>The stable property logical name (for example <c>"email"</c>). Required.</summary>
    public string? Name { get; set; }
}
