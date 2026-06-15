using System.Security.Cryptography;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.KnownAnswerTests;

/// <summary>
/// Known-answer tests for AES-256-GCM, the production suite. The vectors are the published GCM
/// test cases (McGrew &amp; Viega / NIST SP 800-38D): fixed key, nonce, plaintext and AAD with
/// fixed expected ciphertext and tag. They verify the platform <see cref="AesGcm"/> primitive the
/// service relies on; no expected value is produced by our own code.
/// </summary>
public sealed class AesGcmKnownAnswerTests
{
    private const string ZeroKey256 = "0000000000000000000000000000000000000000000000000000000000000000";
    private const string ZeroNonce = "000000000000000000000000";

    [Fact]
    public void Aes256Gcm_EmptyPlaintext_EmptyAad_ProducesKnownTag()
    {
        // GCM Test Case 13 (AES-256).
        var key = Hex.FromHex(ZeroKey256);
        var nonce = Hex.FromHex(ZeroNonce);
        var expectedTag = Hex.FromHex("530f8afbc74536b9a963b4f1c4cb738b");

        var ciphertext = Array.Empty<byte>();
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, ReadOnlySpan<byte>.Empty, ciphertext, tag, ReadOnlySpan<byte>.Empty);

        Assert.Empty(ciphertext);
        Assert.Equal(expectedTag, tag);
    }

    [Fact]
    public void Aes256Gcm_SixteenZeroBytes_ProducesKnownCiphertextAndTag()
    {
        // GCM Test Case 14 (AES-256).
        var key = Hex.FromHex(ZeroKey256);
        var nonce = Hex.FromHex(ZeroNonce);
        var plaintext = Hex.FromHex("00000000000000000000000000000000");
        var expectedCiphertext = Hex.FromHex("cea7403d4d606b6e074ec5d3baf39d18");
        var expectedTag = Hex.FromHex("d0d1c8a799996bf0265b98b5d48ab919");

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, ReadOnlySpan<byte>.Empty);

        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);
    }

    [Fact]
    public void Aes256Gcm_WithAad_ProducesKnownCiphertextAndTag()
    {
        // GCM Test Case 16 (AES-256): non-empty plaintext and additional authenticated data.
        var key = Hex.FromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var nonce = Hex.FromHex("cafebabefacedbaddecaf888");
        var plaintext = Hex.FromHex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        var aad = Hex.FromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        var expectedCiphertext = Hex.FromHex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662");
        var expectedTag = Hex.FromHex("76fc6ece0f4e1768cddf8853bb2d551b");

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);

        // A wrong AAD must fail authentication.
        var wrongAad = (byte[])aad.Clone();
        wrongAad[0] ^= 0xFF;
        var decrypted = new byte[ciphertext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() => aes.Decrypt(nonce, ciphertext, tag, decrypted, wrongAad));
    }
}
