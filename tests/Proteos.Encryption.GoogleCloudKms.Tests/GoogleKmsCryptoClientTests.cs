using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Proteos.Encryption.GoogleCloudKms;
using Xunit;

namespace Proteos.Encryption.GoogleCloudKms.Tests;

/// <summary>
/// Exercises the CRC32C integrity verification inside <see cref="GoogleKmsCryptoClient"/> by feeding
/// crafted KMS responses through a fake RPC seam — no live Google Cloud connection.
/// </summary>
public sealed class GoogleKmsCryptoClientTests
{
    private const string KeyName = "projects/my-project/locations/europe-west3/keyRings/proteos/cryptoKeys/kek";

    // --- Encrypt / wrap ---

    [Fact]
    public async Task Encrypt_ValidChecksums_ReturnsCiphertext()
    {
        var ciphertext = new byte[] { 1, 2, 3, 4, 5 };
        var rpc = new FakeKmsRpcClient(encrypt: _ => new EncryptResponse
        {
            Name = KeyName,
            Ciphertext = ByteString.CopyFrom(ciphertext),
            CiphertextCrc32C = Crc32C.Compute(ciphertext),
            VerifiedPlaintextCrc32C = true,
        });
        var client = new GoogleKmsCryptoClient(rpc);

        var result = await client.EncryptAsync(KeyName, new byte[] { 9, 9, 9 }, default);

        Assert.Equal(ciphertext, result);
    }

    [Fact]
    public async Task Encrypt_SendsKeyNameAndPlaintextChecksum()
    {
        var plaintext = new byte[] { 9, 9, 9, 9 };
        var ciphertext = new byte[] { 1, 2, 3 };
        var rpc = new FakeKmsRpcClient(encrypt: _ => new EncryptResponse
        {
            Ciphertext = ByteString.CopyFrom(ciphertext),
            CiphertextCrc32C = Crc32C.Compute(ciphertext),
            VerifiedPlaintextCrc32C = true,
        });
        var client = new GoogleKmsCryptoClient(rpc);

        await client.EncryptAsync(KeyName, plaintext, default);

        Assert.Equal(KeyName, rpc.LastEncryptRequest!.Name);
        Assert.Equal((long?)Crc32C.Compute(plaintext), (long?)rpc.LastEncryptRequest!.PlaintextCrc32C);
    }

    [Fact]
    public async Task Encrypt_WrongCiphertextChecksum_ThrowsProviderException()
    {
        var ciphertext = new byte[] { 1, 2, 3, 4, 5 };
        var rpc = new FakeKmsRpcClient(encrypt: _ => new EncryptResponse
        {
            Ciphertext = ByteString.CopyFrom(ciphertext),
            CiphertextCrc32C = Crc32C.Compute(ciphertext) ^ 1u, // corrupted in transit
            VerifiedPlaintextCrc32C = true,
        });
        var client = new GoogleKmsCryptoClient(rpc);

        await Assert.ThrowsAsync<GoogleCloudKmsKeyProviderException>(
            async () => await client.EncryptAsync(KeyName, new byte[] { 9, 9, 9 }, default));
    }

    [Fact]
    public async Task Encrypt_ServerDidNotVerifyRequestChecksum_ThrowsProviderException()
    {
        var ciphertext = new byte[] { 1, 2, 3, 4, 5 };
        var rpc = new FakeKmsRpcClient(encrypt: _ => new EncryptResponse
        {
            Ciphertext = ByteString.CopyFrom(ciphertext),
            CiphertextCrc32C = Crc32C.Compute(ciphertext), // ciphertext checksum is fine...
            VerifiedPlaintextCrc32C = false,                // ...but the server rejected our request checksum
        });
        var client = new GoogleKmsCryptoClient(rpc);

        await Assert.ThrowsAsync<GoogleCloudKmsKeyProviderException>(
            async () => await client.EncryptAsync(KeyName, new byte[] { 9, 9, 9 }, default));
    }

    // --- Decrypt / unwrap ---

    [Fact]
    public async Task Decrypt_ValidChecksum_ReturnsPlaintext()
    {
        var plaintext = new byte[] { 7, 7, 7, 7 };
        var rpc = new FakeKmsRpcClient(decrypt: _ => new DecryptResponse
        {
            Plaintext = ByteString.CopyFrom(plaintext),
            PlaintextCrc32C = Crc32C.Compute(plaintext),
        });
        var client = new GoogleKmsCryptoClient(rpc);

        var result = await client.DecryptAsync(KeyName, new byte[] { 1, 2, 3 }, default);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task Decrypt_SendsKeyNameAndCiphertextChecksum()
    {
        var wrapped = new byte[] { 1, 2, 3, 4 };
        var plaintext = new byte[] { 7, 7 };
        var rpc = new FakeKmsRpcClient(decrypt: _ => new DecryptResponse
        {
            Plaintext = ByteString.CopyFrom(plaintext),
            PlaintextCrc32C = Crc32C.Compute(plaintext),
        });
        var client = new GoogleKmsCryptoClient(rpc);

        await client.DecryptAsync(KeyName, wrapped, default);

        Assert.Equal(KeyName, rpc.LastDecryptRequest!.Name);
        Assert.Equal((long?)Crc32C.Compute(wrapped), (long?)rpc.LastDecryptRequest!.CiphertextCrc32C);
    }

    [Fact]
    public async Task Decrypt_WrongPlaintextChecksum_ThrowsProviderException()
    {
        var plaintext = new byte[] { 7, 7, 7, 7 };
        var rpc = new FakeKmsRpcClient(decrypt: _ => new DecryptResponse
        {
            Plaintext = ByteString.CopyFrom(plaintext),
            PlaintextCrc32C = Crc32C.Compute(plaintext) ^ 1u, // corrupted in transit
        });
        var client = new GoogleKmsCryptoClient(rpc);

        await Assert.ThrowsAsync<GoogleCloudKmsKeyProviderException>(
            async () => await client.DecryptAsync(KeyName, new byte[] { 1, 2, 3 }, default));
    }
}
