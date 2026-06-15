using System.Security.Cryptography;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// Value encryption for the AES-256-GCM suite (suite id <c>0x01</c>). It derives a per-tenant,
/// per-scope key, encrypts under a fresh random nonce with the envelope header as additional
/// authenticated data, and produces a <see cref="CiphertextEnvelope"/>. Decryption reverses this
/// and fails — rather than returning a wrong value — whenever the tenant, scope or key id does
/// not match, or the data was tampered with.
/// </summary>
/// <remarks>
/// The <see cref="IValueEncryptor"/>/<see cref="IValueDecryptor"/> methods operate at the
/// envelope level. <see cref="EncryptToBytes"/> and <see cref="DecryptFromBytes"/> add the
/// serialization round-trip via the codec for callers that work with the stored binary form.
/// Scope is bound through key derivation (never placed in the AAD), and only header fields form
/// the AAD — matching the envelope specification.
/// </remarks>
public sealed class AesGcmValueEncryptionService : IValueEncryptionService
{
    private const int AesKeyByteSize = 32;

    private static readonly CryptoSuiteDefinition Suite = CryptoSuiteRegistry.Aes256Gcm;

    private readonly IKeyMaterialProvider _keyProvider;
    private readonly ICiphertextEnvelopeCodec _codec;
    private readonly INonceSource _nonceSource;

    public AesGcmValueEncryptionService(IKeyMaterialProvider keyProvider, ICiphertextEnvelopeCodec codec)
        : this(keyProvider, codec, RandomNonceSource.Instance)
    {
    }

    internal AesGcmValueEncryptionService(IKeyMaterialProvider keyProvider, ICiphertextEnvelopeCodec codec, INonceSource nonceSource)
    {
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        _codec = codec ?? throw new ArgumentNullException(nameof(codec));
        _nonceSource = nonceSource ?? throw new ArgumentNullException(nameof(nonceSource));
    }

    /// <inheritdoc />
    public CiphertextEnvelope Encrypt(ReadOnlySpan<byte> plaintext, EncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var keyId = _keyProvider.GetCurrentKeyId(context.Tenant);
        var header = new CiphertextEnvelopeHeader(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, keyId);
        var aad = _codec.CreateAad(header);
        var descriptor = new KeyDescriptor(keyId, KeyPurpose.Encryption, context.Scope);

        var key = _keyProvider.DeriveKey(context.Tenant, descriptor);
        try
        {
            var nonce = new byte[Suite.NonceLength];
            _nonceSource.Fill(nonce);

            var tag = new byte[Suite.TagLength];
            var ciphertext = new byte[plaintext.Length];

            using (var aes = CreateAesGcm(key))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }

            return CiphertextEnvelope.Create(header, nonce, tag, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    public byte[] Decrypt(CiphertextEnvelope envelope, EncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(context);

        EnsureSupported(envelope);

        var header = envelope.Header;
        var aad = _codec.CreateAad(header);
        var descriptor = new KeyDescriptor(header.KeyId, KeyPurpose.Encryption, context.Scope);

        var key = _keyProvider.DeriveKey(context.Tenant, descriptor);
        try
        {
            var plaintext = new byte[envelope.Ciphertext.Length];

            using (var aes = CreateAesGcm(key))
            {
                try
                {
                    aes.Decrypt(envelope.Nonce.Span, envelope.Ciphertext.Span, envelope.Tag.Span, plaintext, aad);
                }
                catch (AuthenticationTagMismatchException)
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    throw new ValueDecryptionException(
                        "Decryption failed: the data could not be authenticated. The tenant, scope or key id may be wrong, or the data may be corrupt or tampered with.");
                }
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Encrypts a value and returns the serialized envelope bytes.</summary>
    public byte[] EncryptToBytes(ReadOnlySpan<byte> plaintext, EncryptionContext context) =>
        _codec.Serialize(Encrypt(plaintext, context));

    /// <summary>Parses serialized envelope bytes and decrypts the value.</summary>
    /// <exception cref="EnvelopeParseException">The bytes are not a valid envelope.</exception>
    public byte[] DecryptFromBytes(ReadOnlySpan<byte> envelopeBytes, EncryptionContext context) =>
        Decrypt(_codec.Parse(envelopeBytes), context);

    private static void EnsureSupported(CiphertextEnvelope envelope)
    {
        var header = envelope.Header;

        if (header.Version != EnvelopeVersion.V1)
        {
            throw new NotSupportedException($"Envelope version {header.Version} is not supported.");
        }

        if (header.Suite != CryptoSuiteId.Aes256Gcm)
        {
            throw new NotSupportedException($"Crypto suite {header.Suite} is not supported by the AES-256-GCM service.");
        }

        if (header.AadScheme != AadSchemeId.HeaderBound)
        {
            throw new NotSupportedException($"AAD scheme {header.AadScheme} is not supported.");
        }

        if (envelope.Nonce.Length != Suite.NonceLength)
        {
            throw new NotSupportedException($"Nonce length {envelope.Nonce.Length} is not valid for the AES-256-GCM suite.");
        }

        if (envelope.Tag.Length != Suite.TagLength)
        {
            throw new NotSupportedException($"Tag length {envelope.Tag.Length} is not valid for the AES-256-GCM suite.");
        }
    }

    private static AesGcm CreateAesGcm(byte[] key)
    {
        if (key.Length != AesKeyByteSize)
        {
            throw new InvalidOperationException($"The key provider returned a {key.Length}-byte key; AES-256-GCM requires {AesKeyByteSize} bytes.");
        }

        return new AesGcm(key, Suite.TagLength);
    }
}
