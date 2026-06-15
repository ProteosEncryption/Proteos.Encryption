using Proteos.Encryption.Abstractions;
using Xunit;

namespace Proteos.Encryption.Abstractions.Tests;

public sealed class EnvelopeVersionTests
{
    [Fact]
    public void V1_HasExpectedByte()
    {
        Assert.Equal(0x01, EnvelopeVersion.V1.Value);
    }

    [Fact]
    public void Constructor_WithZero_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new EnvelopeVersion(0));
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        Assert.Equal(EnvelopeVersion.V1, new EnvelopeVersion(0x01));
        Assert.Equal("0x01", EnvelopeVersion.V1.ToString());
    }
}

public sealed class CryptoSuiteIdTests
{
    [Fact]
    public void RegistryEntries_HaveExpectedBytes()
    {
        Assert.Equal(0x01, CryptoSuiteId.Aes256Gcm.Value);
        Assert.Equal(0x02, CryptoSuiteId.Aes256GcmSiv.Value);
        Assert.Equal(0x03, CryptoSuiteId.XChaCha20Poly1305.Value);
        Assert.Equal(0x10, CryptoSuiteId.Aes256SivDeterministic.Value);
    }

    [Fact]
    public void Constructor_WithZero_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CryptoSuiteId(0));
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        Assert.Equal(CryptoSuiteId.Aes256Gcm, new CryptoSuiteId(0x01));
        Assert.NotEqual(CryptoSuiteId.Aes256Gcm, CryptoSuiteId.Aes256GcmSiv);
    }
}

public sealed class CiphertextEnvelopeHeaderTests
{
    private static KeyId KeyId() => Proteos.Encryption.Abstractions.KeyId.FromBytes([1, 2, 3]);

    private static CiphertextEnvelopeHeader Header() =>
        new(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, KeyId());

    [Fact]
    public void Constructor_WithValidArguments_Succeeds()
    {
        var header = Header();

        Assert.Equal(EnvelopeVersion.V1, header.Version);
        Assert.Equal(CryptoSuiteId.Aes256Gcm, header.Suite);
        Assert.Equal(AadSchemeId.HeaderBound, header.AadScheme);
    }

    [Fact]
    public void Constructor_WithNullKeyId_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CiphertextEnvelopeHeader(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, null!));
    }

    [Fact]
    public void Constructor_WithDefaultVersion_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new CiphertextEnvelopeHeader(default, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, KeyId()));
    }

    [Fact]
    public void Constructor_WithDefaultSuite_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new CiphertextEnvelopeHeader(EnvelopeVersion.V1, default, AadSchemeId.HeaderBound, KeyId()));
    }

    [Fact]
    public void Constructor_WithDefaultAadScheme_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new CiphertextEnvelopeHeader(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, default, KeyId()));
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        Assert.Equal(Header(), Header());
        Assert.True(Header() == Header());
        Assert.Equal(Header().GetHashCode(), Header().GetHashCode());
    }

    [Fact]
    public void Equality_DistinguishesKeyId()
    {
        var a = Header();
        var b = new CiphertextEnvelopeHeader(
            EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound,
            Proteos.Encryption.Abstractions.KeyId.FromBytes([9, 9, 9]));

        Assert.NotEqual(a, b);
    }
}

public sealed class CiphertextEnvelopeTests
{
    private static CiphertextEnvelopeHeader Header() =>
        new(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, KeyId.FromBytes([1]));

    private static CiphertextEnvelope Envelope() =>
        CiphertextEnvelope.Create(Header(), [1, 2], [3, 4], [5, 6, 7]);

    [Fact]
    public void Create_WithValidArguments_Succeeds()
    {
        var envelope = Envelope();

        Assert.Equal(new byte[] { 1, 2 }, envelope.Nonce.ToArray());
        Assert.Equal(new byte[] { 3, 4 }, envelope.Tag.ToArray());
        Assert.Equal(new byte[] { 5, 6, 7 }, envelope.Ciphertext.ToArray());
    }

    [Fact]
    public void Create_WithNullHeader_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => CiphertextEnvelope.Create(null!, [1], [2], [3]));
    }

    [Fact]
    public void Create_WithEmptyNonce_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => CiphertextEnvelope.Create(Header(), ReadOnlySpan<byte>.Empty, [2], [3]));
    }

    [Fact]
    public void Create_WithEmptyTag_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => CiphertextEnvelope.Create(Header(), [1], ReadOnlySpan<byte>.Empty, [3]));
    }

    [Fact]
    public void Create_WithEmptyCiphertext_IsAllowed()
    {
        var envelope = CiphertextEnvelope.Create(Header(), [1, 2], [3, 4], ReadOnlySpan<byte>.Empty);

        Assert.Equal(0, envelope.Ciphertext.Length);
    }

    [Fact]
    public void Create_CopiesInput_SoLaterMutationDoesNotLeak()
    {
        var nonce = new byte[] { 1, 2 };
        var envelope = CiphertextEnvelope.Create(Header(), nonce, [3, 4], [5, 6]);

        nonce[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2 }, envelope.Nonce.ToArray());
    }

    [Fact]
    public void NonceToArray_ReturnsDefensiveCopy()
    {
        var envelope = Envelope();

        var copy = envelope.NonceToArray();
        copy[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2 }, envelope.Nonce.ToArray());
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        Assert.Equal(Envelope(), Envelope());
        Assert.True(Envelope() == Envelope());
        Assert.Equal(Envelope().GetHashCode(), Envelope().GetHashCode());
    }

    [Fact]
    public void Equality_DistinguishesCiphertext()
    {
        var a = Envelope();
        var b = CiphertextEnvelope.Create(Header(), [1, 2], [3, 4], [5, 6, 8]);

        Assert.NotEqual(a, b);
    }
}
