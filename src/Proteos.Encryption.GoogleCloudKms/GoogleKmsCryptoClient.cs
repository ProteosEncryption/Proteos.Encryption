using Google.Cloud.Kms.V1;
using Google.Protobuf;

namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// The production <see cref="IGoogleKmsCryptoClient"/>: it builds the Cloud KMS requests, sends them
/// through the raw <see cref="IKmsRpcClient"/> seam, and verifies the responses. It uses symmetric Cloud
/// KMS <c>Encrypt</c>/<c>Decrypt</c> on an <c>ENCRYPT_DECRYPT</c> CryptoKey — the key never leaves KMS —
/// and references the CryptoKey (not a version), so KMS selects the primary version on encrypt and the
/// matching version on decrypt. CRC32C checksums are sent and verified on every call so corruption in
/// transit fails closed rather than producing a bad wrap/unwrap. It deliberately does <b>not</b> use
/// <c>GenerateDataKey</c>-style flows: the tenant master key already exists and is supplied for wrapping.
/// </summary>
internal sealed class GoogleKmsCryptoClient : IGoogleKmsCryptoClient
{
    private readonly IKmsRpcClient _rpc;

    public GoogleKmsCryptoClient(IKmsRpcClient rpc)
    {
        _rpc = rpc ?? throw new ArgumentNullException(nameof(rpc));
    }

    public async ValueTask<byte[]> EncryptAsync(string keyName, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken)
    {
        var request = new EncryptRequest
        {
            Name = keyName,
            Plaintext = ByteString.CopyFrom(plaintextKey.Span),
            PlaintextCrc32C = Crc32C.Compute(plaintextKey.Span),
        };

        var response = await _rpc.EncryptAsync(request, cancellationToken).ConfigureAwait(false);

        // Server confirms it received our plaintext intact, and we confirm we received the ciphertext intact.
        if (!response.VerifiedPlaintextCrc32C)
        {
            throw new GoogleCloudKmsKeyProviderException(
                $"Google Cloud KMS encrypt (wrap) integrity check failed for key '{keyName}': the server did not verify the request checksum.");
        }

        if (response.CiphertextCrc32C != Crc32C.Compute(response.Ciphertext.Span))
        {
            throw new GoogleCloudKmsKeyProviderException(
                $"Google Cloud KMS encrypt (wrap) integrity check failed for key '{keyName}': the response ciphertext checksum did not match.");
        }

        return response.Ciphertext.ToByteArray();
    }

    public async ValueTask<byte[]> DecryptAsync(string keyName, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken)
    {
        var request = new DecryptRequest
        {
            Name = keyName,
            Ciphertext = ByteString.CopyFrom(wrappedKey.Span),
            CiphertextCrc32C = Crc32C.Compute(wrappedKey.Span),
        };

        var response = await _rpc.DecryptAsync(request, cancellationToken).ConfigureAwait(false);

        // We confirm we received the plaintext intact. (KMS rejects a bad request checksum server-side.)
        if (response.PlaintextCrc32C != Crc32C.Compute(response.Plaintext.Span))
        {
            throw new GoogleCloudKmsKeyProviderException(
                $"Google Cloud KMS decrypt (unwrap) integrity check failed for key '{keyName}': the response plaintext checksum did not match.");
        }

        return response.Plaintext.ToByteArray();
    }
}
