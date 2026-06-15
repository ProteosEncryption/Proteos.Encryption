using System.Security.Cryptography;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.KnownAnswerTests;

/// <summary>
/// Known-answer tests for HKDF-SHA256 using the RFC 5869 Appendix A test vectors. The expected
/// PRK and OKM are the fixed values from the RFC, not produced by our own code. Test Case 3 uses
/// an empty salt, which matches the production <see cref="Hkdf"/> wrapper, so that wrapper is
/// verified directly against the RFC.
/// </summary>
public sealed class HkdfKnownAnswerTests
{
    // RFC 5869, Appendix A.1 — Test Case 1 (SHA-256, with salt and info).
    private const string Tc1Ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    private const string Tc1Salt = "000102030405060708090a0b0c";
    private const string Tc1Info = "f0f1f2f3f4f5f6f7f8f9";
    private const string Tc1Prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    private const string Tc1Okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

    // RFC 5869, Appendix A.3 — Test Case 3 (SHA-256, empty salt and info).
    private const string Tc3Ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    private const string Tc3Okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8";

    [Fact]
    public void HkdfSha256_Extract_TestCase1_MatchesRfcPrk()
    {
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, Hex.FromHex(Tc1Ikm), Hex.FromHex(Tc1Salt));

        Assert.Equal(Tc1Prk, Hex.ToHex(prk));
    }

    [Fact]
    public void HkdfSha256_DeriveKey_TestCase1_MatchesRfcOkm()
    {
        var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, Hex.FromHex(Tc1Ikm), 42, Hex.FromHex(Tc1Salt), Hex.FromHex(Tc1Info));

        Assert.Equal(Tc1Okm, Hex.ToHex(okm));
    }

    [Fact]
    public void HkdfSha256_DeriveKey_TestCase3_MatchesRfcOkm()
    {
        var okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, Hex.FromHex(Tc3Ikm), 42, salt: Array.Empty<byte>(), info: Array.Empty<byte>());

        Assert.Equal(Tc3Okm, Hex.ToHex(okm));
    }

    [Fact]
    public void ProductionHkdfWrapper_TestCase3_MatchesRfcOkm()
    {
        // The wrapper uses SHA-256 with an empty salt, so RFC Test Case 3 (empty salt and info) is a
        // direct known-answer test for it.
        var okm = Hkdf.DeriveKey(Hex.FromHex(Tc3Ikm), info: ReadOnlySpan<byte>.Empty, length: 42);

        Assert.Equal(Tc3Okm, Hex.ToHex(okm));
    }
}
