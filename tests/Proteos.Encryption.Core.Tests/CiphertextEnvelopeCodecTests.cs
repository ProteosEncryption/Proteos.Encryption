using System.Buffers.Binary;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests;

public sealed class CiphertextEnvelopeRoundtripTests
{
    [Fact]
    public void Serialize_Then_Parse_YieldsEqualEnvelope()
    {
        var envelope = CodecTestFixture.Envelope();

        var parsed = CodecTestFixture.Codec.Parse(CodecTestFixture.Codec.Serialize(envelope));

        Assert.Equal(envelope, parsed);
    }

    [Fact]
    public void Roundtrip_WithEmptyCiphertext_Succeeds()
    {
        var envelope = CodecTestFixture.Envelope([]);

        var parsed = CodecTestFixture.Codec.Parse(CodecTestFixture.Codec.Serialize(envelope));

        Assert.Equal(envelope, parsed);
        Assert.Equal(0, parsed.Ciphertext.Length);
    }

    [Fact]
    public void Roundtrip_WithLargeCiphertext_Succeeds()
    {
        var ciphertext = Enumerable.Range(0, 4096).Select(i => (byte)i).ToArray();
        var envelope = CodecTestFixture.Envelope(ciphertext);

        var parsed = CodecTestFixture.Codec.Parse(CodecTestFixture.Codec.Serialize(envelope));

        Assert.Equal(envelope, parsed);
    }

    [Fact]
    public void TryParse_OnValidBuffer_ReturnsTrueWithoutError()
    {
        var bytes = CodecTestFixture.ValidBytes();

        var ok = CodecTestFixture.Codec.TryParse(bytes, out var envelope, out var error);

        Assert.True(ok);
        Assert.Null(error);
        Assert.Equal(CodecTestFixture.Envelope(), envelope);
    }

    [Fact]
    public void Parse_CopiesInput_SoLaterMutationDoesNotLeak()
    {
        var bytes = CodecTestFixture.ValidBytes();
        var parsed = CodecTestFixture.Codec.Parse(bytes);

        bytes[CodecTestFixture.NonceOffset] ^= 0xFF;

        Assert.Equal(CodecTestFixture.Envelope(), parsed);
    }

    [Fact]
    public void Serialize_ReturnsFreshArray_NotAliasedAcrossCalls()
    {
        var first = CodecTestFixture.Codec.Serialize(CodecTestFixture.Envelope());
        var second = CodecTestFixture.Codec.Serialize(CodecTestFixture.Envelope());

        Assert.Equal(first, second);

        first[0] ^= 0xFF;

        Assert.NotEqual(first, second);
    }
}

public sealed class CiphertextEnvelopeFormatLayoutTests
{
    [Fact]
    public void Serialized_StartsWithMagic()
    {
        var bytes = CodecTestFixture.ValidBytes();

        Assert.True(CiphertextEnvelopeFormat.StartsWithMagic(bytes));
        Assert.Equal(CiphertextEnvelopeFormat.GetMagic(), bytes[..CiphertextEnvelopeFormat.MagicLength]);
    }

    [Fact]
    public void Serialized_HasExactExpectedLength_WithNoTrailingBytes()
    {
        var ciphertext = new byte[7];
        var expected = CiphertextEnvelopeFormat.FixedOverheadLength
                       + CodecTestFixture.KeyIdBytes.Length
                       + CodecTestFixture.Nonce().Length
                       + CodecTestFixture.Tag().Length
                       + ciphertext.Length;

        var bytes = CodecTestFixture.ValidBytes(ciphertext);

        Assert.Equal(expected, bytes.Length);
    }

    [Fact]
    public void CiphertextLength_IsUInt32BigEndian()
    {
        var ciphertext = new byte[258]; // 0x0000_0102
        var bytes = CodecTestFixture.ValidBytes(ciphertext);

        var lengthField = bytes.AsSpan(CodecTestFixture.CiphertextLengthOffset, 4);

        Assert.Equal(new byte[] { 0x00, 0x00, 0x01, 0x02 }, lengthField.ToArray());
        Assert.Equal(258u, BinaryPrimitives.ReadUInt32BigEndian(lengthField));
    }

    [Fact]
    public void HeaderBytes_AppearInDeclaredOrder()
    {
        var bytes = CodecTestFixture.ValidBytes();

        Assert.Equal(EnvelopeVersion.V1.Value, bytes[CodecTestFixture.VersionOffset]);
        Assert.Equal(CryptoSuiteId.Aes256Gcm.Value, bytes[CodecTestFixture.SuiteOffset]);
        Assert.Equal(AadSchemeId.HeaderBound.Value, bytes[CodecTestFixture.AadSchemeOffset]);
        Assert.Equal(CodecTestFixture.KeyIdBytes.Length, bytes[CodecTestFixture.KeyIdLengthOffset]);
        Assert.Equal(12, bytes[CodecTestFixture.NonceLengthOffset]);
        Assert.Equal(16, bytes[CodecTestFixture.TagLengthOffset]);
    }
}

public sealed class CiphertextEnvelopeAadTests
{
    [Fact]
    public void CreateAad_IsHeaderFieldsFollowedByKeyId()
    {
        var header = CodecTestFixture.Header();

        var aad = CodecTestFixture.Codec.CreateAad(header);

        var expected = new byte[3 + CodecTestFixture.KeyIdBytes.Length];
        expected[0] = EnvelopeVersion.V1.Value;
        expected[1] = CryptoSuiteId.Aes256Gcm.Value;
        expected[2] = AadSchemeId.HeaderBound.Value;
        CodecTestFixture.KeyIdBytes.CopyTo(expected, 3);

        Assert.Equal(expected, aad);
    }

    [Fact]
    public void CreateAad_ExcludesMagicAndLengthPrefixes()
    {
        var aad = CodecTestFixture.Codec.CreateAad(CodecTestFixture.Header());

        Assert.Equal(3 + CodecTestFixture.KeyIdBytes.Length, aad.Length);
        Assert.False(CiphertextEnvelopeFormat.StartsWithMagic(aad));
    }

    [Fact]
    public void CreateAad_BindsKeyId()
    {
        var a = CodecTestFixture.Codec.CreateAad(CodecTestFixture.Header());
        var other = new CiphertextEnvelopeHeader(
            EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound,
            KeyId.FromBytes(Enumerable.Repeat((byte)0xEE, 18).ToArray()));

        var b = CodecTestFixture.Codec.CreateAad(other);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void CreateAad_WithNullHeader_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => CodecTestFixture.Codec.CreateAad(null!));
    }
}

public sealed class CiphertextEnvelopeSerializeValidationTests
{
    [Fact]
    public void Serialize_WithNullEnvelope_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => CodecTestFixture.Codec.Serialize(null!));
    }

    [Fact]
    public void Serialize_RejectsReservedSuite()
    {
        var header = new CiphertextEnvelopeHeader(
            EnvelopeVersion.V1, CryptoSuiteId.Aes256GcmSiv, AadSchemeId.HeaderBound, KeyId.FromBytes(CodecTestFixture.KeyIdBytes));
        var envelope = CiphertextEnvelope.Create(header, CodecTestFixture.Nonce(), CodecTestFixture.Tag(), [0x01]);

        Assert.Throws<ArgumentException>(() => CodecTestFixture.Codec.Serialize(envelope));
    }

    [Fact]
    public void Serialize_RejectsNonGcmNonceLength()
    {
        var header = CodecTestFixture.Header();
        var envelope = CiphertextEnvelope.Create(header, new byte[11], CodecTestFixture.Tag(), [0x01]);

        Assert.Throws<ArgumentException>(() => CodecTestFixture.Codec.Serialize(envelope));
    }

    [Fact]
    public void Serialize_RejectsNonGcmTagLength()
    {
        var header = CodecTestFixture.Header();
        var envelope = CiphertextEnvelope.Create(header, CodecTestFixture.Nonce(), new byte[15], [0x01]);

        Assert.Throws<ArgumentException>(() => CodecTestFixture.Codec.Serialize(envelope));
    }
}
