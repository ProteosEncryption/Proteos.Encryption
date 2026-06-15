namespace Proteos.Encryption.Core;

/// <summary>
/// Normalizes a value to a canonical form before it is fed into a blind index, so that values
/// considered equal produce the same index. Normalization must be deterministic and
/// culture-invariant; it influences which values match and is therefore a fixed, documented part
/// of a field's configuration.
/// </summary>
public interface IBlindIndexNormalizer
{
    string Normalize(string value);
}
