using Microsoft.Extensions.DependencyInjection.Extensions;
using Proteos.Encryption.AwsKms;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration for the AWS KMS key provider. Lives in the
/// <c>Microsoft.Extensions.DependencyInjection</c> namespace so it sits next to the other Proteos
/// registration calls. It registers <see cref="AwsKmsKeyProvider"/> only — wiring it into a
/// <c>RegistryKeyMaterialProvider</c> as the <c>KeyProviderKind.AwsKms</c> provider stays in the
/// application's own configuration, keeping this package free of the registry and derivation layers.
/// </summary>
public static class ProteosAwsKmsServiceCollectionExtensions
{
    /// <summary>Registers an <see cref="AwsKmsKeyProvider"/> as a singleton from the given options.</summary>
    /// <exception cref="ArgumentNullException">Services or configuration is null.</exception>
    /// <exception cref="InvalidOperationException">No KMS key reference was configured.</exception>
    /// <exception cref="ArgumentException">The configured key reference is not a valid KMS reference.</exception>
    public static IServiceCollection AddProteosAwsKms(this IServiceCollection services, Action<AwsKmsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AwsKmsOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.KeyId))
        {
            throw new InvalidOperationException(
                "AddProteosAwsKms requires AwsKmsOptions.KeyId to be set to a KMS key ARN, alias ARN, key id, or 'alias/<name>'.");
        }

        // Validate the reference up front (fail fast at startup, not at the first wrap). The AWS client
        // itself is built lazily when the provider is first resolved.
        var keyReference = AwsKmsKeyReference.Parse(options.KeyId);
        var region = options.Region;

        services.TryAddSingleton(_ => AwsKmsKeyProvider.Create(keyReference, region));
        return services;
    }
}
