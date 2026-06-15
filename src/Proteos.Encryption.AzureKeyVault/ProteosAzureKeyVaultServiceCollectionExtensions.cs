using Azure.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Proteos.Encryption.AzureKeyVault;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration for the Azure Key Vault key provider. Lives in the
/// <c>Microsoft.Extensions.DependencyInjection</c> namespace so it sits next to the other Proteos
/// registration calls. It registers <see cref="AzureKeyVaultKeyProvider"/> only — wiring it into a
/// <c>RegistryKeyMaterialProvider</c> as the <c>KeyProviderKind.AzureKeyVault</c> provider stays in the
/// application's own configuration, keeping this package free of the registry and derivation layers.
/// </summary>
public static class ProteosAzureKeyVaultServiceCollectionExtensions
{
    /// <summary>Registers an <see cref="AzureKeyVaultKeyProvider"/> as a singleton from the given options.</summary>
    /// <exception cref="ArgumentNullException">Services or configuration is null.</exception>
    /// <exception cref="InvalidOperationException">No key identifier was configured.</exception>
    /// <exception cref="ArgumentException">The configured key identifier is not a valid Key Vault key identifier.</exception>
    public static IServiceCollection AddProteosAzureKeyVault(this IServiceCollection services, Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AzureKeyVaultOptions();
        configure(options);

        if (options.KeyIdentifier is null)
        {
            throw new InvalidOperationException(
                "AddProteosAzureKeyVault requires AzureKeyVaultOptions.KeyIdentifier to be set to the Key Vault key identifier URI.");
        }

        // Validate the reference up front (fail fast at startup, not at the first wrap), and default the
        // credential to DefaultAzureCredential without forcing it.
        var keyReference = AzureKeyVaultKeyReference.Parse(options.KeyIdentifier.ToString());
        var credential = options.Credential ?? new DefaultAzureCredential();

        services.TryAddSingleton(_ => new AzureKeyVaultKeyProvider(keyReference, credential));
        return services;
    }
}
