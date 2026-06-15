namespace Proteos.Encryption.Abstractions;

/// <summary>
/// A neutral, opaque reference to a provider-specific key — for example an Azure Key Vault key URI,
/// an AWS KMS key ARN or a Google Cloud KMS resource name. It pairs the provider kind with the
/// vendor's own identifier, so the key model stays free of vendor SDK types; the matching
/// <see cref="IKeyProvider"/> adapter is what interprets <see cref="Reference"/>.
/// </summary>
public sealed record ProviderKeyReference
{
    /// <summary>The provider that understands <see cref="Reference"/>.</summary>
    public KeyProviderKind Provider { get; }

    /// <summary>The vendor-specific key identifier (URI, ARN, resource name). Opaque to Proteos.</summary>
    public string Reference { get; }

    /// <summary>Creates a provider key reference.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The provider kind is not a defined value.</exception>
    /// <exception cref="ArgumentException">The reference is null, empty or whitespace.</exception>
    public ProviderKeyReference(KeyProviderKind provider, string reference)
    {
        if (!Enum.IsDefined(provider))
        {
            throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unknown key provider kind.");
        }

        if (string.IsNullOrWhiteSpace(reference))
        {
            throw new ArgumentException("Provider key reference must be a non-empty, non-whitespace value.", nameof(reference));
        }

        Provider = provider;
        Reference = reference.Trim();
    }

    public override string ToString() => $"{Provider}:{Reference}";
}
