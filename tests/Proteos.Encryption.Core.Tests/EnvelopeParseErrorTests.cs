using System.Buffers.Binary;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests;

public sealed class EnvelopeParseErrorTests
{
    private static void AssertError(byte[] data, EnvelopeParseErrorCode expected)
    {
        var ok = CodecTestFixture.Codec.TryParse(data, out var envelope, out var error);

        Assert.False(ok);
        Assert.Null(envelope);
        Assert.NotNull(error);
        Assert.Equal(expected, error!.Code);

        var exception = Assert.Throws<EnvelopeParseException>(() => { CodecTestFixture.Codec.Parse(data); });
        Assert.Equal(expected, exception.Code);
    }

    [Fact]
    public void BufferShorterThanMagic_IsTooShort()
    {
        AssertError(new byte[3], EnvelopeParseErrorCode.TooShort);
    }

    [Fact]
    public void MagicOnly_IsTooShort_BeforeFixedHeader()
    {
        AssertError(CiphertextEnvelopeFormat.GetMagic(), EnvelopeParseErrorCode.TooShort);
    }

    [Fact]
    public void WrongMagic_IsInvalidMagic()
    {
        AssertError(new byte[24], EnvelopeParseErrorCode.InvalidMagic);
    }

    [Fact]
    public void UnknownVersion_IsUnsupportedVersion()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.VersionOffset] = 0x02;

        AssertError(bytes, EnvelopeParseErrorCode.UnsupportedVersion);
    }

    [Fact]
    public void ZeroSuite_IsUnknownSuite()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.SuiteOffset] = 0x00;

        AssertError(bytes, EnvelopeParseErrorCode.UnknownSuite);
    }

    [Fact]
    public void UnregisteredSuite_IsUnknownSuite()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.SuiteOffset] = 0x7F;

        AssertError(bytes, EnvelopeParseErrorCode.UnknownSuite);
    }

    [Fact]
    public void ReservedSuite_IsUnsupportedSuite()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.SuiteOffset] = CryptoSuiteId.Aes256GcmSiv.Value;

        AssertError(bytes, EnvelopeParseErrorCode.UnsupportedSuite);
    }

    [Fact]
    public void UnregisteredAadScheme_IsUnknownAadScheme()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.AadSchemeOffset] = 0x7F;

        AssertError(bytes, EnvelopeParseErrorCode.UnknownAadScheme);
    }

    [Fact]
    public void ReservedAadScheme_IsUnsupportedAadScheme()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.AadSchemeOffset] = AadSchemeId.ContextBound.Value;

        AssertError(bytes, EnvelopeParseErrorCode.UnsupportedAadScheme);
    }

    [Fact]
    public void ZeroKeyIdLength_IsInvalidKeyIdLength()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.KeyIdLengthOffset] = 0x00;

        AssertError(bytes, EnvelopeParseErrorCode.InvalidKeyIdLength);
    }

    [Fact]
    public void KeyIdLengthBeyondBuffer_IsKeyIdTruncated()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.KeyIdLengthOffset] = 0xFF;

        AssertError(bytes, EnvelopeParseErrorCode.KeyIdTruncated);
    }

    [Fact]
    public void NonGcmNonceLength_IsInvalidNonceLength()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.NonceLengthOffset] = 11;

        AssertError(bytes, EnvelopeParseErrorCode.InvalidNonceLength);
    }

    [Fact]
    public void NonceBeyondBuffer_IsNonceTruncated()
    {
        var bytes = CodecTestFixture.ValidBytes();
        // Keep a valid nonce length (12) but cut the buffer right after it.
        var truncated = bytes[..(CodecTestFixture.NonceLengthOffset + 1)];

        AssertError(truncated, EnvelopeParseErrorCode.NonceTruncated);
    }

    [Fact]
    public void NonGcmTagLength_IsInvalidTagLength()
    {
        var bytes = CodecTestFixture.ValidBytes();
        bytes[CodecTestFixture.TagLengthOffset] = 15;

        AssertError(bytes, EnvelopeParseErrorCode.InvalidTagLength);
    }

    [Fact]
    public void TagBeyondBuffer_IsTagTruncated()
    {
        var bytes = CodecTestFixture.ValidBytes();
        var truncated = bytes[..(CodecTestFixture.TagLengthOffset + 1)];

        AssertError(truncated, EnvelopeParseErrorCode.TagTruncated);
    }

    [Fact]
    public void CiphertextLengthGreaterThanRemaining_IsCiphertextTooLong()
    {
        var bytes = CodecTestFixture.ValidBytes(); // ciphertext length 3
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(CodecTestFixture.CiphertextLengthOffset), 99);

        AssertError(bytes, EnvelopeParseErrorCode.CiphertextTooLong);
    }

    [Fact]
    public void BytesAfterCiphertext_IsTrailingData()
    {
        var bytes = CodecTestFixture.ValidBytes();
        var withTrailing = bytes.Concat(new byte[] { 0x01, 0x02, 0x03 }).ToArray();

        AssertError(withTrailing, EnvelopeParseErrorCode.TrailingData);
    }
}
