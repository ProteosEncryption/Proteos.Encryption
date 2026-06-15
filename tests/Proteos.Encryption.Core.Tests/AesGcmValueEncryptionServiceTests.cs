using System.Buffers.Binary;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests;

internal static class EncryptionTestFixture
{
    public static AesGcmValueEncryptionService Service() =>
        new(LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey(), new CiphertextEnvelopeCodec());

    public static EncryptionContext Context(string tenant = "acme", string property = "Email") =>
        new(new TenantId(tenant), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName(property)));

    public static byte[] Plaintext(int length) => Enumerable.Range(0, length).Select(i => (byte)(i * 7 + 3)).ToArray();
}

public sealed class AesGcmRoundtripTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(1024)]
    public void Roundtrip_RecoversPlaintext(int length)
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var plaintext = EncryptionTestFixture.Plaintext(length);

        var decrypted = service.DecryptFromBytes(service.EncryptToBytes(plaintext, context), context);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Roundtrip_AtEnvelopeLevel_RecoversPlaintext()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var plaintext = EncryptionTestFixture.Plaintext(40);

        var envelope = service.Encrypt(plaintext, context);
        var decrypted = service.Decrypt(envelope, context);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesAesGcmHeaderWithCorrectSizes()
    {
        var service = EncryptionTestFixture.Service();
        var plaintext = EncryptionTestFixture.Plaintext(50);

        var envelope = service.Encrypt(plaintext, EncryptionTestFixture.Context());

        Assert.Equal(CryptoSuiteId.Aes256Gcm, envelope.Header.Suite);
        Assert.Equal(EnvelopeVersion.V1, envelope.Header.Version);
        Assert.Equal(AadSchemeId.HeaderBound, envelope.Header.AadScheme);
        Assert.Equal(12, envelope.Nonce.Length);
        Assert.Equal(16, envelope.Tag.Length);
        Assert.Equal(plaintext.Length, envelope.Ciphertext.Length);
    }

    [Fact]
    public void Serialized_CiphertextLengthField_MatchesPlaintextLength()
    {
        var service = EncryptionTestFixture.Service();
        var plaintext = EncryptionTestFixture.Plaintext(258);

        var bytes = service.EncryptToBytes(plaintext, EncryptionTestFixture.Context());

        // The ciphertext occupies the final plaintext.Length bytes; its length field is the 4 bytes before it.
        var lengthField = bytes.AsSpan(bytes.Length - plaintext.Length - 4, 4);
        Assert.Equal((uint)plaintext.Length, BinaryPrimitives.ReadUInt32BigEndian(lengthField));
    }

    [Fact]
    public void Encrypt_IsNonDeterministic_ButBothDecrypt()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var plaintext = EncryptionTestFixture.Plaintext(64);

        var first = service.EncryptToBytes(plaintext, context);
        var second = service.EncryptToBytes(plaintext, context);

        Assert.NotEqual(first, second);
        Assert.Equal(plaintext, service.DecryptFromBytes(first, context));
        Assert.Equal(plaintext, service.DecryptFromBytes(second, context));
    }
}

public sealed class AesGcmFailureTests
{
    [Fact]
    public void Decrypt_WithWrongTenant_Fails()
    {
        var service = EncryptionTestFixture.Service();
        var plaintext = EncryptionTestFixture.Plaintext(32);
        var bytes = service.EncryptToBytes(plaintext, EncryptionTestFixture.Context("acme"));

        Assert.Throws<KeyResolutionException>(() => { service.DecryptFromBytes(bytes, EncryptionTestFixture.Context("globex")); });
    }

    [Fact]
    public void Decrypt_WithWrongScope_Fails()
    {
        var service = EncryptionTestFixture.Service();
        var plaintext = EncryptionTestFixture.Plaintext(32);
        var bytes = service.EncryptToBytes(plaintext, EncryptionTestFixture.Context(property: "Email"));

        Assert.Throws<ValueDecryptionException>(() => { service.DecryptFromBytes(bytes, EncryptionTestFixture.Context(property: "Phone")); });
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Fails()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var bytes = service.EncryptToBytes(EncryptionTestFixture.Plaintext(32), context);

        bytes[^1] ^= 0xFF; // last byte is ciphertext

        Assert.Throws<ValueDecryptionException>(() => { service.DecryptFromBytes(bytes, context); });
    }

    [Fact]
    public void Decrypt_WithTamperedTag_Fails()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var plaintext = EncryptionTestFixture.Plaintext(32);
        var bytes = service.EncryptToBytes(plaintext, context);

        // Tag is the 16 bytes before the 4-byte ciphertext length and the ciphertext itself.
        var tagByte = bytes.Length - plaintext.Length - 4 - 16;
        bytes[tagByte] ^= 0xFF;

        Assert.Throws<ValueDecryptionException>(() => { service.DecryptFromBytes(bytes, context); });
    }

    [Fact]
    public void Decrypt_WithTamperedNonce_Fails()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var bytes = service.EncryptToBytes(EncryptionTestFixture.Plaintext(32), context);

        // Nonce sits right after magic(4)+version(1)+suite(1)+aad(1)+keyIdLen(1)+keyId(18)+nonceLen(1) = 27.
        bytes[27] ^= 0xFF;

        Assert.Throws<ValueDecryptionException>(() => { service.DecryptFromBytes(bytes, context); });
    }

    [Fact]
    public void Decrypt_WithTamperedVersionByte_IsRejectedByParser()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var bytes = service.EncryptToBytes(EncryptionTestFixture.Plaintext(16), context);

        bytes[4] = 0x02; // version

        Assert.Throws<EnvelopeParseException>(() => { service.DecryptFromBytes(bytes, context); });
    }

    [Fact]
    public void Decrypt_WithTamperedKeyIdByte_Fails()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var bytes = service.EncryptToBytes(EncryptionTestFixture.Plaintext(16), context);

        bytes[8] ^= 0xFF; // first key id byte (an AAD-bound header field)

        Assert.Throws<KeyResolutionException>(() => { service.DecryptFromBytes(bytes, context); });
    }

    [Fact]
    public void Decrypt_WithReservedSuite_IsRejected()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var bytes = service.EncryptToBytes(EncryptionTestFixture.Plaintext(16), context);

        bytes[5] = CryptoSuiteId.Aes256GcmSiv.Value; // reserved suite

        var exception = Assert.Throws<EnvelopeParseException>(() => { service.DecryptFromBytes(bytes, context); });
        Assert.Equal(EnvelopeParseErrorCode.UnsupportedSuite, exception.Code);
    }

    [Fact]
    public void Decrypt_WithInvalidEnvelopeBytes_IsRejected()
    {
        var service = EncryptionTestFixture.Service();

        Assert.Throws<EnvelopeParseException>(() => { service.DecryptFromBytes(new byte[5], EncryptionTestFixture.Context()); });
    }

    [Fact]
    public void Decrypt_EnvelopeWithReservedSuite_IsNotSupported()
    {
        var service = EncryptionTestFixture.Service();
        var keyProvider = LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey();
        var context = EncryptionTestFixture.Context();
        var header = new CiphertextEnvelopeHeader(
            EnvelopeVersion.V1, CryptoSuiteId.Aes256GcmSiv, AadSchemeId.HeaderBound, keyProvider.GetCurrentKeyId(context.Tenant));
        var envelope = CiphertextEnvelope.Create(header, new byte[12], new byte[16], new byte[4]);

        Assert.Throws<NotSupportedException>(() => service.Decrypt(envelope, context));
    }

    [Fact]
    public void Encrypt_WithNullContext_IsRejected()
    {
        var service = EncryptionTestFixture.Service();

        Assert.Throws<ArgumentNullException>(() => { service.Encrypt(EncryptionTestFixture.Plaintext(4), null!); });
    }

    [Fact]
    public void Constructor_WithNullDependencies_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new AesGcmValueEncryptionService(null!, new CiphertextEnvelopeCodec()));
        Assert.Throws<ArgumentNullException>(() => new AesGcmValueEncryptionService(LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey(), null!));
    }
}

public sealed class AesGcmSecurityBehaviourTests
{
    [Fact]
    public void MutatingPlaintextAfterEncrypt_DoesNotAffectResult()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var original = EncryptionTestFixture.Plaintext(32);
        var plaintext = (byte[])original.Clone();

        var bytes = service.EncryptToBytes(plaintext, context);
        plaintext[0] ^= 0xFF;

        Assert.Equal(original, service.DecryptFromBytes(bytes, context));
    }

    [Fact]
    public void DecryptedPlaintext_IsAFreshArray()
    {
        var service = EncryptionTestFixture.Service();
        var context = EncryptionTestFixture.Context();
        var original = EncryptionTestFixture.Plaintext(32);
        var bytes = service.EncryptToBytes(original, context);

        var first = service.DecryptFromBytes(bytes, context);
        first[0] ^= 0xFF;
        var second = service.DecryptFromBytes(bytes, context);

        Assert.Equal(original, second);
    }

    [Fact]
    public void EncryptedHeaderKeyId_MatchesProviderCurrentKeyId()
    {
        var keyProvider = LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey();
        var service = new AesGcmValueEncryptionService(keyProvider, new CiphertextEnvelopeCodec());
        var context = EncryptionTestFixture.Context();

        var envelope = service.Encrypt(EncryptionTestFixture.Plaintext(8), context);

        Assert.Equal(keyProvider.GetCurrentKeyId(context.Tenant), envelope.Header.KeyId);
    }
}
