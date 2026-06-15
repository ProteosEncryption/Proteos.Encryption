using Azure.Core;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Proteos.Encryption.AzureKeyVault;

/// <summary>
/// The production <see cref="IKeyVaultWrapClient"/>: a thin adapter over Azure
/// <see cref="CryptographyClient"/> bound to one Key Vault key. Construction is offline (the client is
/// lazy); the first network call happens on wrap or unwrap. Only the RSA-OAEP-256 algorithm is mapped;
/// any other algorithm string is rejected rather than silently substituted.
/// </summary>
internal sealed class KeyVaultWrapClient : IKeyVaultWrapClient
{
    private readonly CryptographyClient _cryptographyClient;

    public KeyVaultWrapClient(AzureKeyVaultKeyReference keyReference, TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(keyReference);
        ArgumentNullException.ThrowIfNull(credential);

        KeyIdentifier = keyReference.KeyIdentifier.ToString();
        _cryptographyClient = new CryptographyClient(keyReference.KeyIdentifier, credential);
    }

    public string KeyIdentifier { get; }

    public async ValueTask<byte[]> WrapKeyAsync(string algorithm, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken)
    {
        var result = await _cryptographyClient
            .WrapKeyAsync(MapAlgorithm(algorithm), plaintextKey.ToArray(), cancellationToken)
            .ConfigureAwait(false);
        return result.EncryptedKey;
    }

    public async ValueTask<byte[]> UnwrapKeyAsync(string algorithm, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken)
    {
        var result = await _cryptographyClient
            .UnwrapKeyAsync(MapAlgorithm(algorithm), wrappedKey.ToArray(), cancellationToken)
            .ConfigureAwait(false);
        return result.Key;
    }

    private static KeyWrapAlgorithm MapAlgorithm(string algorithm)
    {
        if (algorithm == AzureKeyVaultKeyProvider.WrapAlgorithm)
        {
            return KeyWrapAlgorithm.RsaOaep256;
        }

        throw new NotSupportedException(
            $"Unsupported key wrap algorithm '{algorithm}'. Proteos Azure Key Vault supports only {AzureKeyVaultKeyProvider.WrapAlgorithm}.");
    }
}
