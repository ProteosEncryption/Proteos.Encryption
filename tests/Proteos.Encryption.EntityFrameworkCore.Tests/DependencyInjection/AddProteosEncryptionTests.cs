using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.DependencyInjection;

public sealed class AddProteosEncryptionRegistrationTests
{
    private static ServiceProvider BuildProvider() =>
        new ServiceCollection()
            .AddProteosEncryption(options =>
            {
                options.UseLocalDevelopmentKeyProvider();
                options.UseTenant(_ => new TenantId("acme"));
            })
            .BuildServiceProvider();

    [Fact]
    public void RegistersAllServices()
    {
        using var provider = BuildProvider();

        Assert.NotNull(provider.GetService<ICiphertextEnvelopeCodec>());
        Assert.NotNull(provider.GetService<IKeyMaterialProvider>());
        Assert.NotNull(provider.GetService<IValueEncryptionService>());
        Assert.NotNull(provider.GetService<IValueEncryptor>());
        Assert.NotNull(provider.GetService<IValueDecryptor>());
        Assert.NotNull(provider.GetService<IBlindIndexProvider>());
        Assert.NotNull(provider.GetService<ITenantResolver>());
        Assert.NotNull(provider.GetService<DefaultBlindIndexNormalizer>());
        Assert.NotNull(provider.GetService<EmailBlindIndexNormalizer>());
    }

    [Fact]
    public void AllServices_AreSingletons()
    {
        var services = new ServiceCollection().AddProteosEncryption(options =>
        {
            options.UseLocalDevelopmentKeyProvider();
            options.UseTenant(_ => new TenantId("acme"));
        });

        foreach (var serviceType in new[]
                 {
                     typeof(ICiphertextEnvelopeCodec), typeof(IKeyMaterialProvider), typeof(IValueEncryptionService),
                     typeof(IBlindIndexProvider), typeof(ITenantResolver),
                 })
        {
            var descriptor = services.Single(d => d.ServiceType == serviceType);
            Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        }

        using var provider = services.BuildServiceProvider();
        Assert.Same(provider.GetRequiredService<IValueEncryptionService>(), provider.GetRequiredService<IValueEncryptionService>());
    }

    [Fact]
    public void ValueEncryptionInterfaces_ResolveToSameInstance()
    {
        using var provider = BuildProvider();

        var service = provider.GetRequiredService<IValueEncryptionService>();
        Assert.Same(service, provider.GetRequiredService<IValueEncryptor>());
        Assert.Same(service, provider.GetRequiredService<IValueDecryptor>());
        Assert.Same(service, provider.GetRequiredService<AesGcmValueEncryptionService>());
    }

    [Fact]
    public void KeyProvider_IsLocalDevelopment_AndDerivesKeys()
    {
        using var provider = BuildProvider();
        var keyProvider = provider.GetRequiredService<IKeyMaterialProvider>();
        var tenant = new TenantId("acme");

        var keyId = keyProvider.GetCurrentKeyId(tenant);
        var key = keyProvider.DeriveKey(tenant, new KeyDescriptor(keyId, KeyPurpose.Encryption, new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"))));

        Assert.IsType<LocalDevelopmentKeyProvider>(keyProvider);
        Assert.Equal(18, keyId.Length);
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void EndToEnd_EncryptDecrypt_ThroughResolvedServices()
    {
        using var provider = BuildProvider();
        var service = provider.GetRequiredService<AesGcmValueEncryptionService>();
        var resolver = provider.GetRequiredService<ITenantResolver>();
        var context = new EncryptionContext(resolver.Resolve(provider), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));
        var plaintext = "max@example.com"u8.ToArray();

        var decrypted = service.DecryptFromBytes(service.EncryptToBytes(plaintext, context), context);

        Assert.Equal(plaintext, decrypted);
    }
}

public sealed class TenantResolutionTests
{
    private static ServiceProvider Build(Action<ProteosEncryptionOptions> tenant)
    {
        var services = new ServiceCollection().AddProteosEncryption(options =>
        {
            options.UseLocalDevelopmentKeyProvider();
            tenant(options);
        });
        return services.BuildServiceProvider();
    }

    [Fact]
    public void DelegateOverload_ResolvesTenant()
    {
        using var provider = Build(o => o.UseTenant(_ => new TenantId("acme")));

        Assert.Equal(new TenantId("acme"), provider.GetRequiredService<ITenantResolver>().Resolve(provider));
    }

    [Fact]
    public void StringOverload_ResolvesTenant()
    {
        using var provider = Build(o => o.UseTenant(_ => "globex"));

        Assert.Equal(new TenantId("globex"), provider.GetRequiredService<ITenantResolver>().Resolve(provider));
    }

    [Fact]
    public void UseSingleTenant_ResolvesFixedTenant()
    {
        using var provider = Build(o => o.UseSingleTenant("acme"));

        Assert.Equal(new TenantId("acme"), provider.GetRequiredService<ITenantResolver>().Resolve(provider));
    }

    [Fact]
    public void NullTenantResult_IsHardError()
    {
        using var provider = Build(o => o.UseTenant(_ => (TenantId?)null));
        var resolver = provider.GetRequiredService<ITenantResolver>();

        Assert.Throws<ProteosEncryptionException>(() => resolver.Resolve(provider));
    }

    [Fact]
    public void EmptyStringTenant_IsHardError()
    {
        using var provider = Build(o => o.UseTenant(_ => "   "));
        var resolver = provider.GetRequiredService<ITenantResolver>();

        Assert.Throws<ProteosEncryptionException>(() => resolver.Resolve(provider));
    }
}

public sealed class AddProteosEncryptionConfigurationErrorTests
{
    [Fact]
    public void MissingTenantResolver_FailsAtAddTime()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddProteosEncryption(options => options.UseLocalDevelopmentKeyProvider()));
    }

    [Fact]
    public void MissingKeyProvider_FailsAtAddTime()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddProteosEncryption(options => options.UseTenant(_ => new TenantId("acme"))));
    }

    [Fact]
    public void InvalidRootKey_FailsAtConfigurationTime()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() =>
            services.AddProteosEncryption(options =>
            {
                options.UseLocalDevelopmentKeyProvider(new byte[16]); // too short (< 32)
                options.UseTenant(_ => new TenantId("acme"));
            }));
    }

    [Fact]
    public void SecondAddProteosEncryption_Throws()
    {
        var services = new ServiceCollection();
        services.AddProteosEncryption(o =>
        {
            o.UseLocalDevelopmentKeyProvider();
            o.UseTenant(_ => new TenantId("acme"));
        });

        Assert.Throws<InvalidOperationException>(() =>
            services.AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                o.UseTenant(_ => new TenantId("globex"));
            }));
    }

    [Fact]
    public void DoubleKeyProviderConfiguration_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddProteosEncryption(options =>
            {
                options.UseLocalDevelopmentKeyProvider();
                options.UseLocalDevelopmentKeyProvider();
            }));
    }

    [Fact]
    public void DoubleTenantConfiguration_Throws()
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddProteosEncryption(options =>
            {
                options.UseLocalDevelopmentKeyProvider();
                options.UseTenant(_ => new TenantId("acme"));
                options.UseTenant(_ => new TenantId("globex"));
            }));
    }

    [Fact]
    public void NullConfigure_IsRejected()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => services.AddProteosEncryption(null!));
    }
}
