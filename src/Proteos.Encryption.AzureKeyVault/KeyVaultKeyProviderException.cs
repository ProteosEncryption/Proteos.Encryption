using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.AzureKeyVault;

/// <summary>
/// Thrown when an Azure Key Vault wrap or unwrap operation fails. The original Azure failure is kept
/// as the inner exception; the message names the operation and the key identifier only — never any
/// key material, wrapped bytes or plaintext.
/// </summary>
public sealed class KeyVaultKeyProviderException : ProteosEncryptionException
{
    public KeyVaultKeyProviderException(string message)
        : base(message)
    {
    }

    public KeyVaultKeyProviderException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
