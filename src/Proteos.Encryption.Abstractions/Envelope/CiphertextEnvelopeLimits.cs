namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The minimum and maximum lengths of the variable-length envelope fields. The bounds follow
/// directly from the binary layout: key id, nonce and tag each carry a single-byte length
/// prefix (so 1..255), and the ciphertext carries a 32-bit length prefix.
/// </summary>
public static class CiphertextEnvelopeLimits
{
    /// <summary>Minimum key id length in bytes.</summary>
    public const int KeyIdMinLength = 1;

    /// <summary>Maximum key id length in bytes (single-byte length prefix).</summary>
    public const int KeyIdMaxLength = 255;

    /// <summary>Minimum nonce length in bytes.</summary>
    public const int NonceMinLength = 1;

    /// <summary>Maximum nonce length in bytes (single-byte length prefix).</summary>
    public const int NonceMaxLength = 255;

    /// <summary>Minimum authentication tag length in bytes.</summary>
    public const int TagMinLength = 1;

    /// <summary>Maximum authentication tag length in bytes (single-byte length prefix).</summary>
    public const int TagMaxLength = 255;

    /// <summary>Minimum ciphertext length in bytes. An empty plaintext still produces a tag, so zero is valid.</summary>
    public const uint CiphertextMinLength = 0;

    /// <summary>Maximum ciphertext length in bytes (32-bit length prefix).</summary>
    public const uint CiphertextMaxLength = uint.MaxValue;
}
