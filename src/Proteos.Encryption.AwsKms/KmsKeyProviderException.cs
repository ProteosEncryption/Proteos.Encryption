using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.AwsKms;

/// <summary>
/// Thrown when an AWS KMS encrypt (wrap) or decrypt (unwrap) operation fails. The original AWS failure
/// is kept as the inner exception; the message names the operation and the key reference only — never
/// any key material, wrapped bytes or plaintext.
/// </summary>
public sealed class KmsKeyProviderException : ProteosEncryptionException
{
    public KmsKeyProviderException(string message)
        : base(message)
    {
    }

    public KmsKeyProviderException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
