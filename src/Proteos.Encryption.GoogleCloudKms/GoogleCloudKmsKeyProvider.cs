using Google.Apis.Auth.OAuth2;
using Google.Cloud.Kms.V1;
using Grpc.Core;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// An <see cref="IKeyProvider"/> backed by Google Cloud KMS. It implements only the KEK seam — wrap and
/// unwrap of tenant master keys — using one symmetric <c>ENCRYPT_DECRYPT</c> CryptoKey via
/// <c>Encrypt</c>/<c>Decrypt</c>. It knows nothing of EF Core, DbContext, entities, tenant resolution,
/// blind index, re-encryption or any business logic; tenant master-key lifecycle and subkey derivation
/// stay in the crypto core. One provider instance is bound to one CryptoKey; that key wraps many tenant
/// master keys, matching the Proteos hierarchy.
/// </summary>
public sealed class GoogleCloudKmsKeyProvider : IKeyProvider
{
    private readonly GoogleCloudKmsKeyReference _keyReference;
    private readonly IGoogleKmsCryptoClient _client;

    internal GoogleCloudKmsKeyProvider(GoogleCloudKmsKeyReference keyReference, IGoogleKmsCryptoClient client)
    {
        _keyReference = keyReference ?? throw new ArgumentNullException(nameof(keyReference));
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <inheritdoc />
    public string ProviderId => "google-cloud-kms";

    /// <summary>
    /// Builds a provider for the given CryptoKey reference. Authentication uses Application Default
    /// Credentials unless <paramref name="credentialsPath"/> or <paramref name="jsonCredentials"/> is
    /// supplied (at most one); <paramref name="endpoint"/> optionally overrides the KMS service endpoint.
    /// </summary>
    /// <exception cref="ArgumentNullException">The key reference is null.</exception>
    public static GoogleCloudKmsKeyProvider Create(
        GoogleCloudKmsKeyReference keyReference,
        string? credentialsPath = null,
        string? jsonCredentials = null,
        string? endpoint = null)
    {
        ArgumentNullException.ThrowIfNull(keyReference);

        var builder = new KeyManagementServiceClientBuilder { Endpoint = endpoint };

        // When neither explicit credential is supplied the builder uses Application Default Credentials
        // (the production default: Workload Identity / GCE-GKE metadata / GOOGLE_APPLICATION_CREDENTIALS).
        // GoogleCredential.FromFile/FromJson are flagged obsolete in favour of the newer CredentialFactory
        // seam, but remain the stable, documented way to load a service-account key from a path or inline
        // JSON; we keep them deliberately (suppressing CS0618) to honour the simple CredentialsPath /
        // JsonCredentials options without pulling in the heavier factory API.
        if (!string.IsNullOrWhiteSpace(credentialsPath) || !string.IsNullOrWhiteSpace(jsonCredentials))
        {
#pragma warning disable CS0618 // GoogleCredential.FromFile/FromJson are obsolete but stable; see comment above.
            builder.GoogleCredential = !string.IsNullOrWhiteSpace(credentialsPath)
                ? GoogleCredential.FromFile(credentialsPath)
                : GoogleCredential.FromJson(jsonCredentials);
#pragma warning restore CS0618
        }

        return new GoogleCloudKmsKeyProvider(keyReference, new GoogleKmsCryptoClient(new KmsRpcClient(builder.Build())));
    }

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
            var ciphertext = await _client.EncryptAsync(_keyReference.KeyName, plaintextKey, cancellationToken).ConfigureAwait(false);
            return WrappedKey.Create(keyId, ciphertext);
        }
        catch (RpcException exception)
        {
            // Wrap the vendor failure into a Proteos exception. No key material is included in the message.
            throw new GoogleCloudKmsKeyProviderException(
                $"Google Cloud KMS encrypt (wrap) failed for key '{_keyReference.KeyName}'.", exception);
        }
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);

        try
        {
            return await _client.DecryptAsync(_keyReference.KeyName, wrappedKey.Ciphertext, cancellationToken).ConfigureAwait(false);
        }
        catch (RpcException exception)
        {
            throw new GoogleCloudKmsKeyProviderException(
                $"Google Cloud KMS decrypt (unwrap) failed for key '{_keyReference.KeyName}'.", exception);
        }
    }
}
