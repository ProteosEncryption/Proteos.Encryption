namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Encrypts a single field value within an <see cref="EncryptionContext"/>, producing a
/// self-describing ciphertext envelope.
/// </summary>
/// <remarks>
/// The contract is value-level and synchronous: acquiring and caching key material is the
/// concern of the key layer behind <see cref="IKeyProvider"/>, not of the hot path. Null is not
/// represented here — by convention a null field is stored as null and never reaches an
/// encryptor; an empty value is encrypted normally.
/// </remarks>
public interface IValueEncryptor
{
    /// <summary>Encrypts <paramref name="plaintext"/> for the given context.</summary>
    CiphertextEnvelope Encrypt(ReadOnlySpan<byte> plaintext, EncryptionContext context);
}
