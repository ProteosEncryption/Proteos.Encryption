using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.TestSupport;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// End-to-end golden regression with a fixed root key, tenant, scope, plaintext and (via the
/// internal nonce seam) a fixed nonce, so the whole pipeline is deterministic. The expected
/// envelope is OUR OWN golden value, captured once from the implementation; it pins key
/// derivation, AAD construction, AES-GCM usage and the envelope format together. The same golden
/// envelope drives the manipulation regression below.
/// </summary>
public sealed class EndToEndGoldenTests
{
    private const string RootKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string NonceHex = "0102030405060708090a0b0c";
    private const string PlaintextHex = "48656c6c6f2c2050726f74656f7321"; // "Hello, Proteos!"

    private const string ExpectedEnvelopeHex =
        "50454e430101011277b23696f3269acd9e54dbf68613fad100010c0102030405060708090a0b0c10ef7db0e4b485445c06f904d24d48bbd50000000f1d8308c6b70d7b7b0e074d3a38dfc3";

    private static readonly TenantId Tenant = new("tenant-a");

    private static EncryptionContext Context() =>
        new(Tenant, new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));

    private static AesGcmValueEncryptionService Service() =>
        new(new LocalDevelopmentKeyProvider(Hex.FromHex(RootKeyHex)), new CiphertextEnvelopeCodec(), new FixedNonceSource(Hex.FromHex(NonceHex)));

    [Fact]
    public void EncryptToBytes_WithFixedInputsAndNonce_MatchesGolden()
    {
        var bytes = Service().EncryptToBytes(Hex.FromHex(PlaintextHex), Context());

        Assert.Equal(ExpectedEnvelopeHex, Hex.ToHex(bytes));
    }

    [Fact]
    public void DecryptFromBytes_OfGolden_RecoversPlaintext()
    {
        var decrypted = Service().DecryptFromBytes(Hex.FromHex(ExpectedEnvelopeHex), Context());

        Assert.Equal(Hex.FromHex(PlaintextHex), decrypted);
    }

    [Fact]
    public void TamperedCiphertextByte_FailsDecryption()
    {
        var bytes = Hex.FromHex(ExpectedEnvelopeHex);
        bytes[^1] ^= 0xFF; // last byte is ciphertext

        Assert.Throws<ValueDecryptionException>(() => { Service().DecryptFromBytes(bytes, Context()); });
    }

    [Fact]
    public void TamperedTagByte_FailsDecryption()
    {
        var bytes = Hex.FromHex(ExpectedEnvelopeHex);
        bytes[40] ^= 0xFF; // first tag byte (magic4+ver1+suite1+aad1+keyIdLen1+keyId18+nonceLen1+nonce12+tagLen1 = 40)

        Assert.Throws<ValueDecryptionException>(() => { Service().DecryptFromBytes(bytes, Context()); });
    }

    [Fact]
    public void TamperedHeaderByte_FailsParsing()
    {
        var bytes = Hex.FromHex(ExpectedEnvelopeHex);
        bytes[4] = 0x02; // version

        Assert.Throws<EnvelopeParseException>(() => { Service().DecryptFromBytes(bytes, Context()); });
    }
}
