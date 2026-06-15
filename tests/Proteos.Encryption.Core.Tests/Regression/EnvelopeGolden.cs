using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core.Tests.Vectors;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// A fixed, hand-authored golden envelope. The bytes are written out from the version 1 format
/// specification (not produced by the codec), so any change to the binary layout breaks the
/// golden tests. The nonce, tag and ciphertext are arbitrary fixed bytes — this fixture exercises
/// the format, not real cryptography.
/// </summary>
internal static class EnvelopeGolden
{
    public static readonly byte[] KeyIdBytes = Hex.FromHex("aabbccdd");
    public static readonly byte[] Nonce = Hex.FromHex("000102030405060708090a0b");
    public static readonly byte[] Tag = Hex.FromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    public static readonly byte[] Ciphertext = Hex.FromHex("112233");

    // PENC | 01 | 01 | 01 | 04 | aabbccdd | 0c | nonce(12) | 10 | tag(16) | 00000003 | 112233
    public const string EnvelopeHex =
        "50454e4301010104aabbccdd0c000102030405060708090a0b10f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00000003112233";

    // Version | Suite | AadScheme | KeyId
    public const string AadHex = "010101aabbccdd";

    public static byte[] EnvelopeBytes() => Hex.FromHex(EnvelopeHex);

    public static CiphertextEnvelopeHeader Header() =>
        new(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, KeyId.FromBytes(KeyIdBytes));

    public static CiphertextEnvelope Envelope() =>
        CiphertextEnvelope.Create(Header(), Nonce, Tag, Ciphertext);
}
