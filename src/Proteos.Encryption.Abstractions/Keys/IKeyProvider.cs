namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The seam to a key-encryption-key (KEK), typically backed by a KMS/HSM. A provider only wraps
/// and unwraps Tenant Master Keys; the master-key lifecycle and all subkey derivation stay in
/// the crypto core, so concrete providers (local development, Azure Key Vault, AWS KMS) remain
/// thin and free of derivation logic.
/// </summary>
/// <remarks>
/// Security invariant: <see cref="UnwrapAsync"/> returns plaintext key material. The caller owns
/// its lifetime and is responsible for clearing it; the abstraction makes no zeroization promise.
/// </remarks>
public interface IKeyProvider
{
    /// <summary>Stable identifier of this provider, for diagnostics and multi-provider routing.</summary>
    string ProviderId { get; }

    /// <summary>Wraps plaintext master-key material under the KEK identified by <paramref name="keyId"/>.</summary>
    ValueTask<WrappedKey> WrapAsync(KeyId keyId, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Unwraps a previously wrapped master key under the KEK. The returned array is secret
    /// plaintext key material owned by the caller.
    /// </summary>
    ValueTask<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default);
}
