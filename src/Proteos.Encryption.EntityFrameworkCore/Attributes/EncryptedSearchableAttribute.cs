namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Marks a property that is stored encrypted <b>and</b> gets a blind index for exact-match
/// search. Searchable always implies encrypted (this derives from <see cref="EncryptedAttribute"/>),
/// so this single attribute is used instead of also applying <see cref="EncryptedAttribute"/>.
/// </summary>
/// <remarks>
/// <see cref="IndexProperty"/> is optional: when omitted, a shadow property named
/// <c>{PropertyName}Index</c> is created automatically; when given, an existing <c>byte[]</c>
/// property is used.
/// </remarks>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public class EncryptedSearchableAttribute : EncryptedAttribute
{
    public EncryptedSearchableAttribute()
    {
    }

    public EncryptedSearchableAttribute(string name)
        : base(name)
    {
    }

    /// <summary>Optional name of the sibling <c>byte[]</c> property that holds the blind index. Omit for an automatic shadow property.</summary>
    public string? IndexProperty { get; set; }

    /// <summary>Normalizer applied before indexing. Defaults to <see cref="BlindIndexNormalizerKind.Default"/>.</summary>
    public BlindIndexNormalizerKind Normalizer { get; set; } = BlindIndexNormalizerKind.Default;
}
