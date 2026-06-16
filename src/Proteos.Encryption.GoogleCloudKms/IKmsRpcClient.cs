using Google.Cloud.Kms.V1;

namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// The raw Cloud KMS encrypt/decrypt RPC surface — request in, response out, with no integrity logic. It
/// sits one level below <see cref="IGoogleKmsCryptoClient"/> so that the CRC32C verification in
/// <see cref="GoogleKmsCryptoClient"/> can be unit-tested against crafted responses without a live KMS
/// connection. The production implementation (<see cref="KmsRpcClient"/>) forwards to
/// <see cref="KeyManagementServiceClient"/> one-to-one.
/// </summary>
internal interface IKmsRpcClient
{
    ValueTask<EncryptResponse> EncryptAsync(EncryptRequest request, CancellationToken cancellationToken);

    ValueTask<DecryptResponse> DecryptAsync(DecryptRequest request, CancellationToken cancellationToken);
}
