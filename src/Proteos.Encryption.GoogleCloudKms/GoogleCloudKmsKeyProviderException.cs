using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// Thrown when a Google Cloud KMS wrap or unwrap operation fails — either a transport/RPC failure or a
/// CRC32C integrity mismatch. The original failure (when any) is kept as the inner exception; the message
/// names the operation and the CryptoKey resource name only — never any key material, wrapped bytes or
/// plaintext.
/// </summary>
public sealed class GoogleCloudKmsKeyProviderException : ProteosEncryptionException
{
    public GoogleCloudKmsKeyProviderException(string message)
        : base(message)
    {
    }

    public GoogleCloudKmsKeyProviderException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
