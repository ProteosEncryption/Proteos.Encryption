using Azure.Core;

namespace Proteos.Encryption.AzureKeyVault;

/// <summary>
/// Options for registering the Azure Key Vault key provider. <see cref="KeyIdentifier"/> is the KEK's
/// Key Vault key identifier URI; <see cref="Credential"/> is optional and defaults to a
/// <c>DefaultAzureCredential</c> when not set, so managed identity / environment / CLI authentication
/// work without forcing a specific credential — yet any <see cref="TokenCredential"/> can be supplied.
/// </summary>
public sealed class AzureKeyVaultOptions
{
    /// <summary>
    /// The Key Vault key identifier URI of the key-encryption-key, for example
    /// <c>https://my-vault.vault.azure.net/keys/proteos-kek/abcdef0123</c>. Pinning a version is
    /// recommended so unwrap stays correct after KEK rotation.
    /// </summary>
    public Uri? KeyIdentifier { get; set; }

    /// <summary>
    /// The credential used to authenticate to Key Vault. Optional: when null, a
    /// <c>DefaultAzureCredential</c> is used.
    /// </summary>
    public TokenCredential? Credential { get; set; }
}
