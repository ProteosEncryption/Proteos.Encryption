using Microsoft.Extensions.DependencyInjection.Extensions;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration for Proteos encryption. Lives in the <c>Microsoft.Extensions.DependencyInjection</c>
/// namespace so it sits next to <c>AddDbContext</c> without an extra using.
/// </summary>
public static class ProteosEncryptionServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Proteos encryption services (envelope codec, value encryption service, blind
    /// index provider, normalizers, key provider and tenant resolver). All are singletons —
    /// stateless and thread-safe; the only per-operation state, the tenant, is resolved fresh from
    /// the current scope by <see cref="ITenantResolver"/>, never cached. Configuration is validated
    /// here, so a missing key provider or tenant resolver fails at startup.
    /// </summary>
    /// <exception cref="ArgumentNullException">Services or configuration is null.</exception>
    /// <exception cref="InvalidOperationException">Called more than once, or the configuration is incomplete.</exception>
    public static IServiceCollection AddProteosEncryption(this IServiceCollection services, Action<ProteosEncryptionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (services.Any(descriptor => descriptor.ServiceType == typeof(ProteosEncryptionMarker)))
        {
            throw new InvalidOperationException("AddProteosEncryption has already been called; call it exactly once.");
        }

        var options = new ProteosEncryptionOptions();
        configure(options);
        options.Validate();

        services.AddSingleton(new ProteosEncryptionMarker());
        services.AddSingleton(new ProteosEncryptionRuntimeOptions(options.StrictMode));

        var keyProviderFactory = options.KeyProviderFactory;
        services.TryAddSingleton<IKeyMaterialProvider>(sp => keyProviderFactory(sp));

        services.TryAddSingleton<ICiphertextEnvelopeCodec, CiphertextEnvelopeCodec>();

        services.TryAddSingleton<AesGcmValueEncryptionService>();
        services.TryAddSingleton<IValueEncryptionService>(sp => sp.GetRequiredService<AesGcmValueEncryptionService>());
        services.TryAddSingleton<IValueEncryptor>(sp => sp.GetRequiredService<AesGcmValueEncryptionService>());
        services.TryAddSingleton<IValueDecryptor>(sp => sp.GetRequiredService<AesGcmValueEncryptionService>());

        services.TryAddSingleton<IBlindIndexProvider, HmacBlindIndexProvider>();
        services.TryAddSingleton(DefaultBlindIndexNormalizer.Instance);
        services.TryAddSingleton(EmailBlindIndexNormalizer.Instance);

        services.TryAddSingleton(options.BuildTenantResolver());

        services.TryAddScoped<EncryptingSaveChangesInterceptor>();
        services.TryAddScoped<DecryptingMaterializationInterceptor>();

        services.TryAddSingleton<IEncryptionMigrationPlanner, EncryptionMigrationPlanner>();
        services.TryAddSingleton<IEncryptionMigrationService, EncryptionMigrationService>();

        return services;
    }
}
