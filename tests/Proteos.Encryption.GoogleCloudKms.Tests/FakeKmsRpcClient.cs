using Google.Cloud.Kms.V1;
using Proteos.Encryption.GoogleCloudKms;

namespace Proteos.Encryption.GoogleCloudKms.Tests;

/// <summary>
/// A test double for <see cref="IKmsRpcClient"/> — the raw KMS RPC seam. It records the request it was
/// called with and returns a caller-crafted response, so the CRC32C verification in
/// <see cref="GoogleKmsCryptoClient"/> can be exercised (including corrupted/false-checksum responses)
/// without any Google Cloud call.
/// </summary>
internal sealed class FakeKmsRpcClient : IKmsRpcClient
{
    private readonly Func<EncryptRequest, EncryptResponse>? _encrypt;
    private readonly Func<DecryptRequest, DecryptResponse>? _decrypt;

    public FakeKmsRpcClient(
        Func<EncryptRequest, EncryptResponse>? encrypt = null,
        Func<DecryptRequest, DecryptResponse>? decrypt = null)
    {
        _encrypt = encrypt;
        _decrypt = decrypt;
    }

    public EncryptRequest? LastEncryptRequest { get; private set; }

    public DecryptRequest? LastDecryptRequest { get; private set; }

    public ValueTask<EncryptResponse> EncryptAsync(EncryptRequest request, CancellationToken cancellationToken)
    {
        LastEncryptRequest = request;
        return ValueTask.FromResult(_encrypt?.Invoke(request) ?? throw new InvalidOperationException("No encrypt behaviour configured."));
    }

    public ValueTask<DecryptResponse> DecryptAsync(DecryptRequest request, CancellationToken cancellationToken)
    {
        LastDecryptRequest = request;
        return ValueTask.FromResult(_decrypt?.Invoke(request) ?? throw new InvalidOperationException("No decrypt behaviour configured."));
    }
}
