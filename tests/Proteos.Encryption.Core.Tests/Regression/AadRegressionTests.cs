using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// Golden regression for AAD construction: <c>Version || CryptoSuiteId || AadSchemeId || KeyId</c>.
/// The expected AAD is fixed bytes hand-derived from the header — the magic marker, the length
/// prefixes and the nonce/tag/ciphertext are deliberately absent.
/// </summary>
public sealed class AadRegressionTests
{
    private static readonly CiphertextEnvelopeCodec Codec = new();

    [Fact]
    public void CreateAad_ProducesExactGoldenBytes()
    {
        var aad = Codec.CreateAad(EnvelopeGolden.Header());

        Assert.Equal(EnvelopeGolden.AadHex, Hex.ToHex(aad));
    }

    [Fact]
    public void Aad_DoesNotContainMagic()
    {
        var aad = Codec.CreateAad(EnvelopeGolden.Header());

        Assert.False(CiphertextEnvelopeFormat.StartsWithMagic(aad));
    }

    [Fact]
    public void Aad_EndsWithKeyId_AndHasNoLengthPrefix()
    {
        var aad = Codec.CreateAad(EnvelopeGolden.Header());

        // Exactly three header bytes plus the key id; no length-prefix byte anywhere.
        Assert.Equal(3 + EnvelopeGolden.KeyIdBytes.Length, aad.Length);
        Assert.Equal(EnvelopeGolden.KeyIdBytes, aad[^EnvelopeGolden.KeyIdBytes.Length..]);
    }

    [Fact]
    public void Aad_DoesNotContainNonceTagOrCiphertext()
    {
        var aad = Codec.CreateAad(EnvelopeGolden.Header());

        Assert.False(ContainsSequence(aad, EnvelopeGolden.Nonce));
        Assert.False(ContainsSequence(aad, EnvelopeGolden.Tag));
        Assert.False(ContainsSequence(aad, EnvelopeGolden.Ciphertext));
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle) =>
        haystack.AsSpan().IndexOf(needle) >= 0;
}
