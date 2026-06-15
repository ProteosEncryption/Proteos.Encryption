namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Semantic shorthand for an encrypted, searchable email field: equivalent to
/// <c>[EncryptedSearchable(name, Normalizer = BlindIndexNormalizerKind.Email)]</c>. The normalizer
/// is chosen by the attribute type — an explicit, unambiguous choice, not inferred from the
/// property name.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class EncryptedEmailAttribute : EncryptedSearchableAttribute
{
    public EncryptedEmailAttribute()
    {
        Normalizer = BlindIndexNormalizerKind.Email;
    }

    public EncryptedEmailAttribute(string name)
        : base(name)
    {
        Normalizer = BlindIndexNormalizerKind.Email;
    }
}
