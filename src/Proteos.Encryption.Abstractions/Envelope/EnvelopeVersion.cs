namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Version of the ciphertext envelope <b>format</b>, kept separate from the cryptographic suite
/// so the two evolve independently. An unknown version is rejected loudly by the codec rather
/// than silently downgraded.
/// </summary>
public readonly record struct EnvelopeVersion
{
    /// <summary>The raw version byte. <c>default</c> (0) is an unspecified, invalid sentinel.</summary>
    public byte Value { get; }

    /// <summary>Creates an envelope version from a non-zero byte.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero.</exception>
    public EnvelopeVersion(byte value)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Envelope version must be non-zero.");
        }

        Value = value;
    }

    /// <summary>The Foundation Release envelope format version.</summary>
    public static readonly EnvelopeVersion V1 = new(0x01);

    public override string ToString() => $"0x{Value:X2}";
}
