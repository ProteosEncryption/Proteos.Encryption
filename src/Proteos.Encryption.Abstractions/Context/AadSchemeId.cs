namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Single-byte identifier of the scheme by which Additional Authenticated Data is formed for a
/// ciphertext envelope. Carried in the envelope header so the binding rules travel with the
/// data and can evolve additively without a format break. A scheme id is never repurposed.
/// </summary>
public readonly record struct AadSchemeId
{
    /// <summary>The raw registry byte. <c>default</c> (0) is an unspecified, invalid sentinel.</summary>
    public byte Value { get; }

    /// <summary>Creates an AAD scheme id from a non-zero registry byte.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero.</exception>
    public AadSchemeId(byte value)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "AAD scheme id must be non-zero.");
        }

        Value = value;
    }

    /// <summary>
    /// Foundation Release scheme: AAD is the serialized envelope header
    /// (<c>EnvelopeVersion ‖ SuiteId ‖ AadSchemeId ‖ KeyId</c>), giving metadata integrity and
    /// downgrade protection. Context binding lives in the key derivation, not in the AAD.
    /// </summary>
    public static readonly AadSchemeId HeaderBound = new(0x01);

    /// <summary>
    /// Reserved: header plus an opt-in binding of the entity primary key. Deferred because the
    /// key is database-generated on insert and mutable. Not implemented in the Foundation Release.
    /// </summary>
    public static readonly AadSchemeId ContextBound = new(0x02);

    public override string ToString() => $"0x{Value:X2}";
}
