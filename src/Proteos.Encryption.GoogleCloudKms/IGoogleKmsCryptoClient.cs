namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// The minimal Cloud KMS surface the provider needs — symmetric encrypt (to wrap a tenant master key)
/// and decrypt (to unwrap it) — abstracted so the provider can be unit-tested without calling Google. The
/// CryptoKey resource name is passed per call so the provider's choice is observable and never hidden. The
/// production implementation wraps <c>KeyManagementServiceClient</c> and performs CRC32C integrity
/// verification internally; tests supply a fake.
/// </summary>
internal interface IGoogleKmsCryptoClient
{
    /// <summary>Encrypts (wraps) plaintext key material under the CryptoKey identified by <paramref name="keyName"/>.</summary>
    ValueTask<byte[]> EncryptAsync(string keyName, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken);

    /// <summary>Decrypts (unwraps) wrapped key material under the CryptoKey identified by <paramref name="keyName"/>.</summary>
    ValueTask<byte[]> DecryptAsync(string keyName, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken);
}
