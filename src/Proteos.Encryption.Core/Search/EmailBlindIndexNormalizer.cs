using System.Text;

namespace Proteos.Encryption.Core;

/// <summary>
/// Normalizer for email-like values: trims, lower-cases invariantly and applies Unicode NFC, so
/// that addresses differing only in case or surrounding whitespace share an index. Lower-casing
/// is invariant (never culture-dependent). This treats the address as case-insensitive, which is
/// the common expectation even though the local part is technically case-sensitive.
/// </summary>
public sealed class EmailBlindIndexNormalizer : IBlindIndexNormalizer
{
    public static readonly EmailBlindIndexNormalizer Instance = new();

    public string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Trim().ToLowerInvariant().Normalize(NormalizationForm.FormC);
    }
}
