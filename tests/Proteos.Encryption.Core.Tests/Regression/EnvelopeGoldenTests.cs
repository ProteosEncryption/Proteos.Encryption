using System.Buffers.Binary;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// Golden regression for the binary envelope format. The expected bytes are hand-authored from
/// the specification, so a format change (field order, magic, endianness) breaks these tests.
/// </summary>
public sealed class EnvelopeGoldenTests
{
    private static readonly CiphertextEnvelopeCodec Codec = new();

    [Fact]
    public void Serialize_ProducesExactGoldenBytes()
    {
        var serialized = Codec.Serialize(EnvelopeGolden.Envelope());

        Assert.Equal(EnvelopeGolden.EnvelopeHex, Hex.ToHex(serialized));
    }

    [Fact]
    public void Parse_GoldenBytes_ProducesExpectedValues()
    {
        var envelope = Codec.Parse(EnvelopeGolden.EnvelopeBytes());

        Assert.Equal(EnvelopeVersion.V1, envelope.Header.Version);
        Assert.Equal(CryptoSuiteId.Aes256Gcm, envelope.Header.Suite);
        Assert.Equal(AadSchemeId.HeaderBound, envelope.Header.AadScheme);
        Assert.Equal(EnvelopeGolden.KeyIdBytes, envelope.Header.KeyId.ToArray());
        Assert.Equal(EnvelopeGolden.Nonce, envelope.Nonce.ToArray());
        Assert.Equal(EnvelopeGolden.Tag, envelope.Tag.ToArray());
        Assert.Equal(EnvelopeGolden.Ciphertext, envelope.Ciphertext.ToArray());
    }

    [Fact]
    public void CiphertextLength_IsBigEndian_NotLittleEndian()
    {
        var bytes = EnvelopeGolden.EnvelopeBytes();
        var lengthField = bytes.AsSpan(bytes.Length - EnvelopeGolden.Ciphertext.Length - 4, 4);

        Assert.Equal((uint)EnvelopeGolden.Ciphertext.Length, BinaryPrimitives.ReadUInt32BigEndian(lengthField));
        Assert.NotEqual((uint)EnvelopeGolden.Ciphertext.Length, BinaryPrimitives.ReadUInt32LittleEndian(lengthField));
    }

    [Fact]
    public void Parse_RejectsTamperedHeaderByte()
    {
        var bytes = EnvelopeGolden.EnvelopeBytes();
        bytes[4] = 0x02; // version

        var exception = Assert.Throws<EnvelopeParseException>(() => { Codec.Parse(bytes); });
        Assert.Equal(EnvelopeParseErrorCode.UnsupportedVersion, exception.Code);
    }
}
