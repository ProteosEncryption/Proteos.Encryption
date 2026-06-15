using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.AzureKeyVault;

/// <summary>
/// An <see cref="IKeyProvider"/> backed by Azure Key Vault. It implements only the KEK seam — wrap and
/// unwrap of tenant master keys — using one Key Vault RSA key and RSA-OAEP-256. It knows nothing of EF
/// Core, DbContext, entities, tenant resolution, blind index, re-encryption or any business logic;
/// tenant master-key lifecycle and subkey derivation stay in the crypto core. One provider instance is
/// bound to one KEK; the per-tenant master keys it wraps are isolated at the master-key layer, matching
/// the Proteos hierarchy where one KEK wraps many tenant master keys.
/// </summary>
public sealed class AzureKeyVaultKeyProvider : IKeyProvider
{
    /// <summary>The only supported key wrap algorithm: RSA-OAEP with SHA-256.</summary>
    public const string WrapAlgorithm = "RSA-OAEP-256";

    private readonly IKeyVaultWrapClient _client;

    /// <summary>Creates a provider for one Key Vault key, authenticating with the given credential.</summary>
    /// <exception cref="ArgumentNullException">The key reference or credential is null.</exception>
    public AzureKeyVaultKeyProvider(AzureKeyVaultKeyReference keyReference, TokenCredential credential)
        : this(new KeyVaultWrapClient(keyReference, credential))
    {
    }

    internal AzureKeyVaultKeyProvider(IKeyVaultWrapClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <inheritdoc />
    public string ProviderId => "azure-key-vault";

    /// <inheritdoc />
    public async ValueTask<WrappedKey> WrapAsync(KeyId keyId, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        if (plaintextKey.IsEmpty)
        {
            throw new ArgumentException("Plaintext key material must not be empty.", nameof(plaintextKey));
        }

        try
        {
            var ciphertext = await _client.WrapKeyAsync(WrapAlgorithm, plaintextKey, cancellationToken).ConfigureAwait(false);
            return WrappedKey.Create(keyId, ciphertext);
        }
        catch (Exception exception) when (exception is RequestFailedException or CryptographicException)
        {
            // Wrap the vendor failure into a Proteos exception. No key material is included in the message.
            throw new KeyVaultKeyProviderException(
                $"Azure Key Vault wrap failed for key '{_client.KeyIdentifier}' using {WrapAlgorithm}.", exception);
        }
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);

        try
        {
            return await _client.UnwrapKeyAsync(WrapAlgorithm, wrappedKey.Ciphertext, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is RequestFailedException or CryptographicException)
        {
            throw new KeyVaultKeyProviderException(
                $"Azure Key Vault unwrap failed for key '{_client.KeyIdentifier}' using {WrapAlgorithm}.", exception);
        }
    }
}
