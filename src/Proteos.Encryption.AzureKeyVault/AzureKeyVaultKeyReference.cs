using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.AzureKeyVault;

/// <summary>
/// A validated Azure Key Vault key identifier — the key-encryption-key (KEK) that wraps tenant master
/// keys. It is parsed from the full key identifier URI
/// <c>https://{vault-host}/keys/{name}[/{version}]</c>, the canonical form the Azure SDK consumes, and
/// exposes its parts. Pinning a version makes unwrap deterministic across KEK rotation; a version-less
/// identifier always resolves to the vault's current key version.
/// </summary>
public sealed class AzureKeyVaultKeyReference
{
    private AzureKeyVaultKeyReference(Uri keyIdentifier, Uri vaultUri, string keyName, string? keyVersion)
    {
        KeyIdentifier = keyIdentifier;
        VaultUri = vaultUri;
        KeyName = keyName;
        KeyVersion = keyVersion;
    }

    /// <summary>The full key identifier URI, as Azure's CryptographyClient consumes it.</summary>
    public Uri KeyIdentifier { get; }

    /// <summary>The vault base URI (scheme + authority).</summary>
    public Uri VaultUri { get; }

    /// <summary>The key name within the vault.</summary>
    public string KeyName { get; }

    /// <summary>The pinned key version, or null when the identifier targets the current version.</summary>
    public string? KeyVersion { get; }

    /// <summary>True when a specific key version is pinned (recommended for rotation-safe unwrap).</summary>
    public bool HasVersion => KeyVersion is not null;

    /// <summary>Parses and validates an Azure Key Vault key identifier URI.</summary>
    /// <exception cref="ArgumentException">The value is not a valid Key Vault key identifier.</exception>
    public static AzureKeyVaultKeyReference Parse(string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyIdentifier);

        if (!Uri.TryCreate(keyIdentifier.Trim(), UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"'{keyIdentifier}' is not a valid absolute URI.", nameof(keyIdentifier));
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"An Azure Key Vault key identifier must use https, but the scheme was '{uri.Scheme}'.", nameof(keyIdentifier));
        }

        // Expected path: /keys/{name} or /keys/{name}/{version}.
        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length is < 2 or > 3 || !string.Equals(segments[0], "keys", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"'{keyIdentifier}' is not a Key Vault key identifier. Expected 'https://<vault-host>/keys/<name>[/<version>]'.",
                nameof(keyIdentifier));
        }

        var vaultUri = new Uri(uri.GetLeftPart(UriPartial.Authority));
        var keyName = segments[1];
        var keyVersion = segments.Length == 3 ? segments[2] : null;

        return new AzureKeyVaultKeyReference(uri, vaultUri, keyName, keyVersion);
    }

    /// <summary>
    /// Interprets a vendor-neutral <see cref="ProviderKeyReference"/> as an Azure Key Vault key
    /// identifier. The reference must be for <see cref="KeyProviderKind.AzureKeyVault"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">The reference is null.</exception>
    /// <exception cref="ArgumentException">The reference is for another provider, or is not a valid key identifier.</exception>
    public static AzureKeyVaultKeyReference FromProviderKeyReference(ProviderKeyReference reference)
    {
        ArgumentNullException.ThrowIfNull(reference);

        if (reference.Provider != KeyProviderKind.AzureKeyVault)
        {
            throw new ArgumentException(
                $"Provider key reference is for '{reference.Provider}', not {KeyProviderKind.AzureKeyVault}.",
                nameof(reference));
        }

        return Parse(reference.Reference);
    }

    /// <summary>Returns the full key identifier URI.</summary>
    public override string ToString() => KeyIdentifier.ToString();
}
