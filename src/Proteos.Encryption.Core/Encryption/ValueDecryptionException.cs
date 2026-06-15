using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// Thrown when a value cannot be decrypted because authentication fails — the wrong tenant,
/// scope or key was used, or the data was corrupted or tampered with. The message is generic
/// and never contains key material, plaintext or ciphertext.
/// </summary>
public sealed class ValueDecryptionException : ProteosEncryptionException
{
    public ValueDecryptionException(string message)
        : base(message)
    {
    }
}
