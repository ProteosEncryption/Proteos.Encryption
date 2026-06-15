namespace Proteos.Encryption.AzureKeyVault;

/// <summary>
/// The minimal wrap/unwrap surface the provider needs from Azure Key Vault, abstracted so the provider
/// can be unit-tested without a live vault. The production implementation wraps Azure's
/// <c>CryptographyClient</c>; tests supply a fake. The algorithm is passed explicitly so the provider's
/// choice (RSA-OAEP-256) is observable and never silently substituted.
/// </summary>
internal interface IKeyVaultWrapClient
{
    /// <summary>The key identifier this client operates on, for diagnostics. Never secret material.</summary>
    string KeyIdentifier { get; }

    /// <summary>Wraps plaintext key material under the configured KEK using the given algorithm.</summary>
    ValueTask<byte[]> WrapKeyAsync(string algorithm, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken);

    /// <summary>Unwraps wrapped key material under the configured KEK using the given algorithm.</summary>
    ValueTask<byte[]> UnwrapKeyAsync(string algorithm, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken);
}
