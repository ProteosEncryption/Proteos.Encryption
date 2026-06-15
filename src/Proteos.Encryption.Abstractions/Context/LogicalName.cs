namespace Proteos.Encryption.Abstractions;

/// <summary>
/// A stable logical name for an entity or property, decoupled from the CLR class/property name.
/// Logical names are bound into the key derivation (HKDF <c>info</c>) to defend against
/// cross-column relocation; pinning them in configuration makes a C# rename safe for already
/// stored data.
/// </summary>
/// <remarks>
/// Names are case-sensitive: their stability is a configuration responsibility. Surrounding
/// whitespace is trimmed; control characters are rejected so the canonical, length-prefixed
/// UTF-8 encoding used by the crypto core stays well-defined.
/// </remarks>
public sealed record LogicalName
{
    /// <summary>Maximum length, in characters, of a logical name.</summary>
    public const int MaxLength = 128;

    /// <summary>The normalised (trimmed) logical name.</summary>
    public string Value { get; }

    /// <summary>Creates a logical name. Surrounding whitespace is trimmed.</summary>
    /// <exception cref="ArgumentException">The value is null, empty, whitespace, too long, or contains control characters.</exception>
    public LogicalName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Logical name must be a non-empty, non-whitespace value.", nameof(value));
        }

        var normalized = value.Trim();

        if (normalized.Length > MaxLength)
        {
            throw new ArgumentException($"Logical name must not exceed {MaxLength} characters.", nameof(value));
        }

        foreach (var character in normalized)
        {
            if (char.IsControl(character))
            {
                throw new ArgumentException("Logical name must not contain control characters.", nameof(value));
            }
        }

        Value = normalized;
    }

    public override string ToString() => Value;
}
