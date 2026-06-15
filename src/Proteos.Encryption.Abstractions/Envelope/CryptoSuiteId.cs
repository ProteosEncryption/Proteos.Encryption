namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Single-byte identifier of the cryptographic suite used for an envelope. Decoupling the suite
/// from the envelope version gives crypto agility without a format break. A suite id is never
/// repurposed; reserved values are declared here to protect them from reuse.
/// </summary>
public readonly record struct CryptoSuiteId
{
    /// <summary>The raw registry byte. <c>default</c> (0) is an unspecified, invalid sentinel.</summary>
    public byte Value { get; }

    /// <summary>Creates a crypto suite id from a non-zero registry byte.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero.</exception>
    public CryptoSuiteId(byte value)
    {
        if (value == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Crypto suite id must be non-zero.");
        }

        Value = value;
    }

    /// <summary>AES-256-GCM. The Foundation Release suite.</summary>
    public static readonly CryptoSuiteId Aes256Gcm = new(0x01);

    /// <summary>Reserved: AES-256-GCM-SIV (nonce-misuse resistant, high volume). Not implemented in the Foundation Release.</summary>
    public static readonly CryptoSuiteId Aes256GcmSiv = new(0x02);

    /// <summary>Reserved: XChaCha20-Poly1305. Not implemented in the Foundation Release.</summary>
    public static readonly CryptoSuiteId XChaCha20Poly1305 = new(0x03);

    /// <summary>Reserved: AES-256-SIV (deterministic, leaks equality). Not implemented in the Foundation Release.</summary>
    public static readonly CryptoSuiteId Aes256SivDeterministic = new(0x10);

    public override string ToString() => $"0x{Value:X2}";
}
