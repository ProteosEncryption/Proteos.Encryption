using System.Collections.Concurrent;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests;

public sealed class LocalDevelopmentKeyProviderTests
{
    private static readonly byte[] RootKey = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static EncryptedDataScope Scope(string property = "Email") =>
        new(new LogicalName("Customer"), new LogicalName(property));

    private static LocalDevelopmentKeyProvider Provider() => new(RootKey);

    private static KeyDescriptor Descriptor(LocalDevelopmentKeyProvider provider, TenantId tenant, KeyPurpose purpose = KeyPurpose.Encryption, string property = "Email") =>
        new(provider.GetCurrentKeyId(tenant), purpose, Scope(property));

    [Fact]
    public void DeriveKey_ReturnsKeyOfExpectedLength()
    {
        var provider = Provider();
        var tenant = new TenantId("acme");

        var key = provider.DeriveKey(tenant, Descriptor(provider, tenant));

        Assert.Equal(LocalDevelopmentKeyProvider.DerivedKeyLength, key.Length);
    }

    [Fact]
    public void DeriveKey_IsDeterministic_AcrossCallsAndInstances()
    {
        var tenant = new TenantId("acme");
        var first = Provider();
        var second = Provider();

        var a = first.DeriveKey(tenant, Descriptor(first, tenant));
        var b = first.DeriveKey(tenant, Descriptor(first, tenant));
        var c = second.DeriveKey(tenant, Descriptor(second, tenant));

        Assert.Equal(a, b);
        Assert.Equal(a, c);
    }

    [Fact]
    public void DeriveKey_DiffersByTenant()
    {
        var provider = Provider();
        var acme = new TenantId("acme");
        var globex = new TenantId("globex");

        var a = provider.DeriveKey(acme, Descriptor(provider, acme));
        var b = provider.DeriveKey(globex, Descriptor(provider, globex));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void DeriveKey_DiffersByPurpose()
    {
        var provider = Provider();
        var tenant = new TenantId("acme");

        var encryption = provider.DeriveKey(tenant, Descriptor(provider, tenant, KeyPurpose.Encryption));
        var blindIndex = provider.DeriveKey(tenant, Descriptor(provider, tenant, KeyPurpose.BlindIndex));

        Assert.NotEqual(encryption, blindIndex);
    }

    [Fact]
    public void DeriveKey_DiffersByScope()
    {
        var provider = Provider();
        var tenant = new TenantId("acme");

        var email = provider.DeriveKey(tenant, Descriptor(provider, tenant, property: "Email"));
        var phone = provider.DeriveKey(tenant, Descriptor(provider, tenant, property: "Phone"));

        Assert.NotEqual(email, phone);
    }

    [Fact]
    public void DeriveKey_DiffersByRootKey()
    {
        var tenant = new TenantId("acme");
        var providerA = new LocalDevelopmentKeyProvider(RootKey);
        var differentRoot = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var providerB = new LocalDevelopmentKeyProvider(differentRoot);

        var a = providerA.DeriveKey(tenant, Descriptor(providerA, tenant));
        var b = providerB.DeriveKey(tenant, Descriptor(providerB, tenant));

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void GetCurrentKeyId_IsDeterministic_AndTenantSpecific()
    {
        var provider = Provider();
        var acme = new TenantId("acme");
        var globex = new TenantId("globex");

        Assert.Equal(provider.GetCurrentKeyId(acme), provider.GetCurrentKeyId(acme));
        Assert.NotEqual(provider.GetCurrentKeyId(acme), provider.GetCurrentKeyId(globex));
        Assert.Equal(18, provider.GetCurrentKeyId(acme).Length);
    }

    [Fact]
    public void DefaultDevelopmentProvider_Works()
    {
        var provider = LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey();
        var tenant = new TenantId("acme");

        var key = provider.DeriveKey(tenant, Descriptor(provider, tenant));

        Assert.Equal(LocalDevelopmentKeyProvider.DerivedKeyLength, key.Length);
        Assert.Equal("local-development-insecure", provider.ProviderId);
    }

    [Fact]
    public void DeriveKey_ReturnsFreshArray_NotInternalState()
    {
        var provider = Provider();
        var tenant = new TenantId("acme");
        var descriptor = Descriptor(provider, tenant);

        var first = provider.DeriveKey(tenant, descriptor);
        first[0] ^= 0xFF;
        var second = provider.DeriveKey(tenant, descriptor);

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Constructor_CopiesRootKey_SoLaterMutationDoesNotLeak()
    {
        var mutableRoot = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var provider = new LocalDevelopmentKeyProvider(mutableRoot);
        var tenant = new TenantId("acme");
        var expected = provider.DeriveKey(tenant, Descriptor(provider, tenant));

        mutableRoot[0] ^= 0xFF;
        var afterMutation = provider.DeriveKey(tenant, Descriptor(provider, tenant));

        Assert.Equal(expected, afterMutation);
    }

    [Fact]
    public void DeriveKey_IsThreadSafe_AndStable()
    {
        var provider = Provider();
        var tenant = new TenantId("acme");
        var descriptor = Descriptor(provider, tenant);
        var expected = provider.DeriveKey(tenant, descriptor);

        var results = new ConcurrentBag<byte[]>();
        Parallel.For(0, 256, _ => results.Add(provider.DeriveKey(tenant, descriptor)));

        Assert.Equal(256, results.Count);
        Assert.All(results, r => Assert.Equal(expected, r));
    }
}

public sealed class LocalDevelopmentKeyProviderErrorTests
{
    private static readonly byte[] RootKey = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static EncryptedDataScope Scope() => new(new LogicalName("Customer"), new LogicalName("Email"));

    [Fact]
    public void Constructor_RejectsTooShortRootKey()
    {
        var tooShort = new byte[LocalDevelopmentKeyProvider.RootKeyMinLength - 1];

        Assert.Throws<ArgumentException>(() => new LocalDevelopmentKeyProvider(tooShort));
    }

    [Fact]
    public void Constructor_RejectsEmptyRootKey()
    {
        Assert.Throws<ArgumentException>(() => new LocalDevelopmentKeyProvider(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void DeriveKey_RejectsNullTenant()
    {
        var provider = new LocalDevelopmentKeyProvider(RootKey);
        var descriptor = new KeyDescriptor(provider.GetCurrentKeyId(new TenantId("acme")), KeyPurpose.Encryption, Scope());

        Assert.Throws<ArgumentNullException>(() => provider.DeriveKey(null!, descriptor));
    }

    [Fact]
    public void DeriveKey_RejectsNullDescriptor()
    {
        var provider = new LocalDevelopmentKeyProvider(RootKey);

        Assert.Throws<ArgumentNullException>(() => provider.DeriveKey(new TenantId("acme"), null!));
    }

    [Fact]
    public void DeriveKey_RejectsKeyIdNotBelongingToTenant()
    {
        var provider = new LocalDevelopmentKeyProvider(RootKey);
        var foreignKeyId = KeyId.FromBytes(Enumerable.Repeat((byte)0xAB, 18).ToArray());
        var descriptor = new KeyDescriptor(foreignKeyId, KeyPurpose.Encryption, Scope());

        Assert.Throws<KeyResolutionException>(() => provider.DeriveKey(new TenantId("acme"), descriptor));
    }

    [Fact]
    public void GetCurrentKeyId_RejectsNullTenant()
    {
        var provider = new LocalDevelopmentKeyProvider(RootKey);

        Assert.Throws<ArgumentNullException>(() => provider.GetCurrentKeyId(null!));
    }
}
