namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Selects the normalizer applied to a value before its blind index is computed. Maps to a
/// concrete normalizer in the crypto core (see the resolver); the mapping is stable because it
/// influences which values match.
/// </summary>
public enum BlindIndexNormalizerKind
{
    /// <summary>Trim and Unicode NFC, case-sensitive.</summary>
    Default = 0,

    /// <summary>Trim, invariant lower-case and Unicode NFC.</summary>
    Email = 1,
}
