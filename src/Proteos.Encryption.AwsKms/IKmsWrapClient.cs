namespace Proteos.Encryption.AwsKms;

/// <summary>
/// The minimal KMS surface the provider needs — symmetric encrypt (to wrap a tenant master key) and
/// decrypt (to unwrap it) — abstracted so the provider can be unit-tested without calling AWS. The key
/// reference is passed per call so the provider's choice is observable and never hidden. The production
/// implementation wraps <c>IAmazonKeyManagementService</c>; tests supply a fake.
/// </summary>
internal interface IKmsWrapClient
{
    /// <summary>Encrypts (wraps) plaintext key material under the KMS key identified by <paramref name="keyId"/>.</summary>
    ValueTask<byte[]> EncryptAsync(string keyId, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken);

    /// <summary>Decrypts (unwraps) wrapped key material, pinning the KMS key identified by <paramref name="keyId"/>.</summary>
    ValueTask<byte[]> DecryptAsync(string keyId, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken);
}
