using Microsoft.Extensions.DependencyInjection.Extensions;
using Proteos.Encryption.GoogleCloudKms;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration for the Google Cloud KMS key provider. Lives in the
/// <c>Microsoft.Extensions.DependencyInjection</c> namespace so it sits next to the other Proteos
/// registration calls. It registers <see cref="GoogleCloudKmsKeyProvider"/> only — wiring it into a
/// <c>RegistryKeyMaterialProvider</c> as the <c>KeyProviderKind.GoogleKms</c> provider stays in the
/// application's own configuration, keeping this package free of the registry and derivation layers.
/// </summary>
public static class ProteosGoogleCloudKmsServiceCollectionExtensions
{
    /// <summary>Registers a <see cref="GoogleCloudKmsKeyProvider"/> as a singleton from the given options.</summary>
    /// <exception cref="ArgumentNullException">Services or configuration is null.</exception>
    /// <exception cref="InvalidOperationException">No key name was configured, or both credential options were set.</exception>
    /// <exception cref="ArgumentException">The configured key name is not a valid CryptoKey resource name.</exception>
    public static IServiceCollection AddProteosGoogleCloudKms(this IServiceCollection services, Action<GoogleCloudKmsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new GoogleCloudKmsOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.KeyName))
        {
            throw new InvalidOperationException(
                "AddProteosGoogleCloudKms requires GoogleCloudKmsOptions.KeyName to be set to the Cloud KMS CryptoKey resource name 'projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<cryptoKey>'.");
        }

        if (!string.IsNullOrWhiteSpace(options.CredentialsPath) && !string.IsNullOrWhiteSpace(options.JsonCredentials))
        {
            throw new InvalidOperationException(
                "AddProteosGoogleCloudKms cannot use both CredentialsPath and JsonCredentials. Set at most one (or neither, for Application Default Credentials).");
        }

        // Validate the reference up front (fail fast at startup, not at the first wrap). The KMS client
        // itself is built lazily when the provider is first resolved.
        var keyReference = GoogleCloudKmsKeyReference.Parse(options.KeyName);
        var credentialsPath = options.CredentialsPath;
        var jsonCredentials = options.JsonCredentials;
        var endpoint = options.Endpoint;

        services.TryAddSingleton(_ => GoogleCloudKmsKeyProvider.Create(keyReference, credentialsPath, jsonCredentials, endpoint));
        return services;
    }
}
