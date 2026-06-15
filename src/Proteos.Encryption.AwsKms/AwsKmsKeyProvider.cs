using Amazon;
using Amazon.KeyManagementService;
using Amazon.Runtime;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.AwsKms;

/// <summary>
/// An <see cref="IKeyProvider"/> backed by AWS KMS. It implements only the KEK seam — wrap and unwrap of
/// tenant master keys — using one symmetric KMS key via <c>Encrypt</c>/<c>Decrypt</c>. It knows nothing
/// of EF Core, DbContext, entities, tenant resolution, blind index, re-encryption or any business logic;
/// tenant master-key lifecycle and subkey derivation stay in the crypto core. One provider instance is
/// bound to one KMS key; that key wraps many tenant master keys, matching the Proteos hierarchy.
/// </summary>
public sealed class AwsKmsKeyProvider : IKeyProvider
{
    private readonly AwsKmsKeyReference _keyReference;
    private readonly IKmsWrapClient _client;

    /// <summary>Creates a provider for one KMS key using the given AWS KMS client.</summary>
    /// <exception cref="ArgumentNullException">The key reference or client is null.</exception>
    public AwsKmsKeyProvider(AwsKmsKeyReference keyReference, IAmazonKeyManagementService kms)
        : this(keyReference, new KmsWrapClient(kms))
    {
    }

    internal AwsKmsKeyProvider(AwsKmsKeyReference keyReference, IKmsWrapClient client)
    {
        _keyReference = keyReference ?? throw new ArgumentNullException(nameof(keyReference));
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <inheritdoc />
    public string ProviderId => "aws-kms";

    /// <summary>
    /// Builds a provider for the given reference, resolving the region from the explicit
    /// <paramref name="region"/>, otherwise from the reference's ARN, otherwise from the AWS SDK default
    /// chain. Credentials always come from the AWS SDK's default credential chain; none is forced.
    /// </summary>
    /// <exception cref="ArgumentNullException">The key reference is null.</exception>
    public static AwsKmsKeyProvider Create(AwsKmsKeyReference keyReference, string? region = null)
    {
        ArgumentNullException.ThrowIfNull(keyReference);

        var resolvedRegion = region ?? keyReference.Region;
        IAmazonKeyManagementService kms = resolvedRegion is null
            ? new AmazonKeyManagementServiceClient()
            : new AmazonKeyManagementServiceClient(RegionEndpoint.GetBySystemName(resolvedRegion));

        return new AwsKmsKeyProvider(keyReference, kms);
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
            var ciphertext = await _client.EncryptAsync(_keyReference.KeyId, plaintextKey, cancellationToken).ConfigureAwait(false);
            return WrappedKey.Create(keyId, ciphertext);
        }
        catch (AmazonServiceException exception)
        {
            // Wrap the vendor failure into a Proteos exception. No key material is included in the message.
            throw new KmsKeyProviderException($"AWS KMS encrypt (wrap) failed for key '{_keyReference.KeyId}'.", exception);
        }
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);

        try
        {
            return await _client.DecryptAsync(_keyReference.KeyId, wrappedKey.Ciphertext, cancellationToken).ConfigureAwait(false);
        }
        catch (AmazonServiceException exception)
        {
            throw new KmsKeyProviderException($"AWS KMS decrypt (unwrap) failed for key '{_keyReference.KeyId}'.", exception);
        }
    }
}
