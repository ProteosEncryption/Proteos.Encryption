namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Identifies which kind of key provider backs a tenant master key version. It is metadata only —
/// the concrete wrap/unwrap is done by the matching <see cref="IKeyProvider"/> adapter — so the
/// neutral key model can describe Azure/AWS/Google (or a custom provider) without referencing any
/// cloud SDK.
/// </summary>
public enum KeyProviderKind
{
    /// <summary>The development-only provider (no KMS). Never for production.</summary>
    LocalDevelopment = 0,

    /// <summary>Azure Key Vault.</summary>
    AzureKeyVault = 1,

    /// <summary>AWS KMS.</summary>
    AwsKms = 2,

    /// <summary>Google Cloud KMS.</summary>
    GoogleKms = 3,

    /// <summary>A custom, caller-supplied provider.</summary>
    Custom = 4,
}
