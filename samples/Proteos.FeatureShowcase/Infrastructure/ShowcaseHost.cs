using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.FeatureShowcase.Infrastructure;

/// <summary>
/// The tiny composition root for the showcase. Every scenario builds its container here, so the whole
/// wiring an application needs is visible in one place and nothing is hidden:
/// <c>AddProteosEncryption(...)</c> + <c>AddDbContext(... UseProteosEncryption(sp))</c> +
/// <c>UseProteosEncryptionModel()</c> in the context. That is the entire setup.
/// </summary>
internal static class ShowcaseHost
{
    public const string Tenant = "showcase";
    public const string DatabaseFile = "showcase.db";

    /// <summary>The zero-config development key provider (single key version). Insecure — never in production.</summary>
    public static IKeyMaterialProvider DevelopmentKey() =>
        LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey();

    /// <summary>
    /// A rotating development key provider that knows versions 1 and 2 and stamps new data with
    /// <paramref name="currentVersion"/>. Used by the rotation scenarios to "switch the current key".
    /// </summary>
    public static LocalDevelopmentKeyProvider Rotating(ushort currentVersion) =>
        LocalDevelopmentKeyProvider.CreateRotating(
            new[]
            {
                new LocalDevelopmentKeyVersion(1, RootKey(1)),
                new LocalDevelopmentKeyVersion(2, RootKey(2)),
            },
            currentVersion);

    /// <summary>Builds a fresh DI container wired to Proteos encryption over SQLite (showcase.db).</summary>
    public static ServiceProvider Build(IKeyMaterialProvider keyProvider, bool strictMode = false)
    {
        var services = new ServiceCollection();

        services.AddProteosEncryption(options =>
        {
            // Development only. Use Azure Key Vault or AWS KMS in production (scenarios 8 and 9).
            options.UseKeyProvider(_ => keyProvider);
            options.UseSingleTenant(Tenant);

            if (strictMode)
            {
                options.EnableStrictMode();
            }
        });

        // The (sp, options) overload is required: it lets the encryption interceptors and the
        // per-operation tenant run inside the resolved scope.
        services.AddDbContext<ShowcaseDbContext>((sp, options) => options
            .UseSqlite($"Data Source={DatabaseFile}")
            .UseProteosEncryption(sp));

        return services.BuildServiceProvider();
    }

    /// <summary>A deterministic 32-byte development root key for one rotation version. Insecure — showcase only.</summary>
    private static byte[] RootKey(byte seed) =>
        Enumerable.Repeat(seed, LocalDevelopmentKeyProvider.RootKeyMinLength).ToArray();
}
