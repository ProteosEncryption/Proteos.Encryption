namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Decrypts a ciphertext envelope within an <see cref="EncryptionContext"/>.
/// </summary>
/// <remarks>
/// Decryption requires the same context that produced the envelope: the tenant selects the
/// master key, and the scope is bound into key derivation. A wrong context, a tampered envelope
/// or an unknown suite/version fails authentication and surfaces as a
/// <see cref="ProteosEncryptionException"/> rather than returning a plausible-but-wrong value.
/// </remarks>
public interface IValueDecryptor
{
    /// <summary>Decrypts <paramref name="envelope"/> for the given context. The returned array is plaintext owned by the caller.</summary>
    byte[] Decrypt(CiphertextEnvelope envelope, EncryptionContext context);
}
