namespace Proteos.Encryption.Core;

/// <summary>
/// Distinct reasons a binary buffer fails to parse as a version 1 ciphertext envelope. Each code
/// names one specific failure so callers can branch (for example, treat
/// <see cref="InvalidMagic"/> as "not an envelope yet" during a backfill) without string matching.
/// </summary>
public enum EnvelopeParseErrorCode
{
    /// <summary>No error. Never carried by an <see cref="EnvelopeParseError"/>; present only as the zero default.</summary>
    None = 0,

    /// <summary>The buffer is too small to contain a required fixed-position field.</summary>
    TooShort,

    /// <summary>The buffer does not begin with the magic marker.</summary>
    InvalidMagic,

    /// <summary>The envelope version is not supported by this release.</summary>
    UnsupportedVersion,

    /// <summary>The crypto suite id is not in the registry.</summary>
    UnknownSuite,

    /// <summary>The crypto suite id is registered but reserved (not implemented).</summary>
    UnsupportedSuite,

    /// <summary>The AAD scheme id is not in the registry.</summary>
    UnknownAadScheme,

    /// <summary>The AAD scheme id is registered but not active in this release.</summary>
    UnsupportedAadScheme,

    /// <summary>The key id length prefix is below the allowed minimum.</summary>
    InvalidKeyIdLength,

    /// <summary>The declared key id length runs past the end of the buffer.</summary>
    KeyIdTruncated,

    /// <summary>The nonce length does not match what the suite requires.</summary>
    InvalidNonceLength,

    /// <summary>The declared nonce length runs past the end of the buffer.</summary>
    NonceTruncated,

    /// <summary>The tag length does not match what the suite requires.</summary>
    InvalidTagLength,

    /// <summary>The declared tag length runs past the end of the buffer.</summary>
    TagTruncated,

    /// <summary>The declared ciphertext length is larger than the bytes remaining in the buffer.</summary>
    CiphertextTooLong,

    /// <summary>Bytes remain in the buffer after the declared ciphertext.</summary>
    TrailingData,
}
