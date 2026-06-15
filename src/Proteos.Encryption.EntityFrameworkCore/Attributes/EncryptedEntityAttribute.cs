namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Declares the stable entity logical name. It is combined with each property's logical name into
/// the scope bound into key derivation, so a class rename does not break stored data. Required on
/// any entity that has encrypted properties.
/// </summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
public sealed class EncryptedEntityAttribute : Attribute
{
    public EncryptedEntityAttribute()
    {
    }

    public EncryptedEntityAttribute(string name)
    {
        Name = name;
    }

    /// <summary>The stable entity logical name (for example <c>"customer"</c>). Required.</summary>
    public string? Name { get; set; }
}
