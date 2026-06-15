using System.Text;

namespace Proteos.Encryption.Core;

/// <summary>
/// The default normalizer: trims surrounding whitespace and applies Unicode NFC. It is
/// case-sensitive. NFC is applied so that canonically equivalent strings (for example a composed
/// vs. decomposed accented character) produce the same index; it is culture-invariant.
/// </summary>
public sealed class DefaultBlindIndexNormalizer : IBlindIndexNormalizer
{
    public static readonly DefaultBlindIndexNormalizer Instance = new();

    public string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Trim().Normalize(NormalizationForm.FormC);
    }
}
