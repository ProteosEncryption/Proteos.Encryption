namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Describes how a blind index is built for a field. In the Foundation Release it carries only
/// the matching semantics; normalization rules and output truncation are added with the search
/// implementation. The field's tenant and logical scope are supplied at call time via the
/// <see cref="EncryptionContext"/>, so they are not duplicated here.
/// </summary>
public sealed record BlindIndexDescriptor
{
    /// <summary>The matching semantics of the index.</summary>
    public BlindIndexPurpose Purpose { get; }

    /// <summary>Creates a blind index descriptor.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Purpose is not a defined value.</exception>
    public BlindIndexDescriptor(BlindIndexPurpose purpose)
    {
        if (!Enum.IsDefined(purpose))
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown blind index purpose.");
        }

        Purpose = purpose;
    }

    /// <summary>Descriptor for exact-match search.</summary>
    public static BlindIndexDescriptor ExactMatch { get; } = new(BlindIndexPurpose.ExactMatch);
}
