namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The formal specification of the version 1 ciphertext envelope: its magic marker, field
/// widths, length-field byte order, derived sizes, the AAD composition and the rules for
/// classifying versions, suites and AAD schemes as known or supported. It defines the format;
/// the serializer and parser that act on it are added in a later step.
/// </summary>
/// <remarks>
/// Binary layout (version 1):
/// <code>
/// Magic            4 bytes   "PENC" (0x50 0x45 0x4E 0x43)
/// Version          1 byte
/// CryptoSuiteId    1 byte
/// AadSchemeId      1 byte
/// KeyIdLength      1 byte    1..255
/// KeyId            N bytes
/// NonceLength      1 byte    1..255
/// Nonce            N bytes
/// TagLength        1 byte    1..255
/// Tag              N bytes
/// CiphertextLength 4 bytes   UInt32 big-endian
/// Ciphertext       N bytes
/// </code>
/// AAD (under <see cref="AadSchemeId.HeaderBound"/>) is the header fields
/// <c>Version || CryptoSuiteId || AadSchemeId || KeyId</c>; the magic marker and the length
/// prefixes are framing and are not authenticated context.
/// </remarks>
public static class CiphertextEnvelopeFormat
{
    private static readonly byte[] MagicBytes = [0x50, 0x45, 0x4E, 0x43];

    /// <summary>Length of the magic marker in bytes.</summary>
    public const int MagicLength = 4;

    /// <summary>The magic marker "PENC" that prefixes every envelope and enables fast "is this encrypted?" detection.</summary>
    public static ReadOnlySpan<byte> Magic => MagicBytes;

    /// <summary>Returns a defensive copy of the magic marker.</summary>
    public static byte[] GetMagic() => (byte[])MagicBytes.Clone();

    /// <summary>Whether <paramref name="data"/> begins with the magic marker.</summary>
    public static bool StartsWithMagic(ReadOnlySpan<byte> data) =>
        data.Length >= MagicLength && data[..MagicLength].SequenceEqual(MagicBytes);

    /// <summary>The format version this specification describes.</summary>
    public static EnvelopeVersion CurrentVersion => EnvelopeVersion.V1;

    /// <summary>Width of the version field in bytes.</summary>
    public const int VersionFieldLength = 1;

    /// <summary>Width of the crypto suite id field in bytes.</summary>
    public const int CryptoSuiteIdFieldLength = 1;

    /// <summary>Width of the AAD scheme id field in bytes.</summary>
    public const int AadSchemeIdFieldLength = 1;

    /// <summary>Width of the key id length prefix in bytes.</summary>
    public const int KeyIdLengthFieldLength = 1;

    /// <summary>Width of the nonce length prefix in bytes.</summary>
    public const int NonceLengthFieldLength = 1;

    /// <summary>Width of the tag length prefix in bytes.</summary>
    public const int TagLengthFieldLength = 1;

    /// <summary>Width of the ciphertext length prefix in bytes.</summary>
    public const int CiphertextLengthFieldLength = 4;

    /// <summary>Byte order of the multi-byte length fields (only the ciphertext length is multi-byte).</summary>
    public const EnvelopeByteOrder LengthFieldByteOrder = EnvelopeByteOrder.BigEndian;

    /// <summary>
    /// Total bytes that are not key id, nonce, tag or ciphertext payload: the magic marker, the
    /// version/suite/scheme bytes and all length prefixes.
    /// </summary>
    public const int FixedOverheadLength =
        MagicLength
        + VersionFieldLength
        + CryptoSuiteIdFieldLength
        + AadSchemeIdFieldLength
        + KeyIdLengthFieldLength
        + NonceLengthFieldLength
        + TagLengthFieldLength
        + CiphertextLengthFieldLength;

    /// <summary>The smallest possible envelope: fixed overhead plus the minimum key id, nonce and tag, with empty ciphertext.</summary>
    public const int MinimumEnvelopeLength =
        FixedOverheadLength
        + CiphertextEnvelopeLimits.KeyIdMinLength
        + CiphertextEnvelopeLimits.NonceMinLength
        + CiphertextEnvelopeLimits.TagMinLength;

    private static readonly EnvelopeAadComponent[] AadComponents =
    [
        EnvelopeAadComponent.Version,
        EnvelopeAadComponent.CryptoSuiteId,
        EnvelopeAadComponent.AadSchemeId,
        EnvelopeAadComponent.KeyId,
    ];

    /// <summary>
    /// The header components, in order, that form the AAD under <see cref="AadSchemeId.HeaderBound"/>.
    /// The magic marker and the length prefixes are deliberately excluded.
    /// </summary>
    public static IReadOnlyList<EnvelopeAadComponent> HeaderAadComponents { get; } = Array.AsReadOnly(AadComponents);

    /// <summary>Whether the envelope format version is supported by this release.</summary>
    public static bool IsSupportedVersion(EnvelopeVersion version) => version == CurrentVersion;

    /// <summary>Whether the suite id is a registered suite (implemented or reserved).</summary>
    public static bool IsKnownSuite(CryptoSuiteId suite) => CryptoSuiteRegistry.IsKnown(suite);

    /// <summary>Whether the suite id is implemented (active) in this release. A reserved or unknown suite is not supported.</summary>
    public static bool IsSupportedSuite(CryptoSuiteId suite) =>
        CryptoSuiteRegistry.TryGet(suite, out var definition) && definition!.IsImplemented;

    /// <summary>Whether the AAD scheme id is a registered scheme (active or reserved).</summary>
    public static bool IsKnownAadScheme(AadSchemeId scheme) =>
        scheme == AadSchemeId.HeaderBound || scheme == AadSchemeId.ContextBound;

    /// <summary>Whether the AAD scheme id is active in this release. Only the header-bound scheme is.</summary>
    public static bool IsSupportedAadScheme(AadSchemeId scheme) => scheme == AadSchemeId.HeaderBound;
}
