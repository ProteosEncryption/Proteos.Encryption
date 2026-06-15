using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.Core.Tests;

/// <summary>
/// Shared building blocks for the codec tests: a canonical valid envelope and the absolute byte
/// offsets of each field in its serialized form (key id is 18 bytes, AES-GCM nonce 12, tag 16).
/// </summary>
internal static class CodecTestFixture
{
    public static readonly CiphertextEnvelopeCodec Codec = new();

    public static readonly byte[] KeyIdBytes = Enumerable.Range(1, 18).Select(i => (byte)i).ToArray();

    public const int VersionOffset = 4;
    public const int SuiteOffset = 5;
    public const int AadSchemeOffset = 6;
    public const int KeyIdLengthOffset = 7;
    public const int KeyIdOffset = 8;

    public static int NonceLengthOffset => KeyIdOffset + KeyIdBytes.Length; // 26
    public static int NonceOffset => NonceLengthOffset + 1;                 // 27
    public static int TagLengthOffset => NonceOffset + 12;                  // 39
    public static int TagOffset => TagLengthOffset + 1;                     // 40
    public static int CiphertextLengthOffset => TagOffset + 16;            // 56

    public static CiphertextEnvelopeHeader Header() =>
        new(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, KeyId.FromBytes(KeyIdBytes));

    public static byte[] Nonce() => Enumerable.Range(0, 12).Select(i => (byte)i).ToArray();

    public static byte[] Tag() => Enumerable.Range(0, 16).Select(i => (byte)(i + 100)).ToArray();

    public static CiphertextEnvelope Envelope(byte[]? ciphertext = null) =>
        CiphertextEnvelope.Create(Header(), Nonce(), Tag(), ciphertext ?? [0xAA, 0xBB, 0xCC]);

    public static byte[] ValidBytes(byte[]? ciphertext = null) => Codec.Serialize(Envelope(ciphertext));
}
