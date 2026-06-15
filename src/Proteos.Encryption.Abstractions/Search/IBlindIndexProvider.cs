namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Computes the blind index of a value, used to populate the shadow column on write and to
/// build the comparison term on query. The index key is derived with the blind-index purpose,
/// keeping it separate from the encryption key.
/// </summary>
public interface IBlindIndexProvider
{
    /// <summary>Computes the blind index of <paramref name="value"/> for the given descriptor and context, using the current key.</summary>
    BlindIndexValue Compute(ReadOnlySpan<byte> value, BlindIndexDescriptor descriptor, EncryptionContext context);

    /// <summary>
    /// Computes the blind index of <paramref name="value"/> under every known key version of the
    /// tenant, so a search can match data written under any version (current or rotated-out). The
    /// default returns only the current-key index (no rotation); a rotation-aware provider overrides it.
    /// </summary>
    IReadOnlyCollection<BlindIndexValue> ComputeForAllKnownKeys(ReadOnlySpan<byte> value, BlindIndexDescriptor descriptor, EncryptionContext context) =>
        [Compute(value, descriptor, context)];
}
