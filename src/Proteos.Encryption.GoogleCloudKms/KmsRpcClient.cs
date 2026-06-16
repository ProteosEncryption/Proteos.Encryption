using Google.Cloud.Kms.V1;

namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// The production <see cref="IKmsRpcClient"/>: a one-to-one pass-through to
/// <see cref="KeyManagementServiceClient"/>. It carries no logic of its own; it exists only so the CRC32C
/// integrity checks in <see cref="GoogleKmsCryptoClient"/> can be unit-tested with a substituted fake,
/// keeping live KMS calls out of the test suite.
/// </summary>
internal sealed class KmsRpcClient : IKmsRpcClient
{
    private readonly KeyManagementServiceClient _client;

    public KmsRpcClient(KeyManagementServiceClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public async ValueTask<EncryptResponse> EncryptAsync(EncryptRequest request, CancellationToken cancellationToken)
        => await _client.EncryptAsync(request, cancellationToken).ConfigureAwait(false);

    public async ValueTask<DecryptResponse> DecryptAsync(DecryptRequest request, CancellationToken cancellationToken)
        => await _client.DecryptAsync(request, cancellationToken).ConfigureAwait(false);
}
