using System.Security.Cryptography;
using System.Text;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.BlindIndex;

public sealed class HmacBlindIndexProviderTests
{
    private static readonly byte[] RootKey = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static EncryptionContext Context(string tenant = "acme", string property = "Email") =>
        new(new TenantId(tenant), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName(property)));

    private static HmacBlindIndexProvider Provider() => new(new LocalDevelopmentKeyProvider(RootKey));

    [Fact]
    public void CreateIndex_IsDeterministic()
    {
        var provider = Provider();
        var context = Context();

        var first = provider.CreateIndex("max@example.com", context, BlindIndexPurpose.ExactMatch);
        var second = provider.CreateIndex("max@example.com", context, BlindIndexPurpose.ExactMatch);

        Assert.Equal(first, second);
    }

    [Fact]
    public void CreateIndex_DiffersByTenant()
    {
        var provider = Provider();

        var acme = provider.CreateIndex("max@example.com", Context("acme"), BlindIndexPurpose.ExactMatch);
        var globex = provider.CreateIndex("max@example.com", Context("globex"), BlindIndexPurpose.ExactMatch);

        Assert.NotEqual(acme, globex);
    }

    [Fact]
    public void CreateIndex_DiffersByScope()
    {
        var provider = Provider();

        var email = provider.CreateIndex("max@example.com", Context(property: "Email"), BlindIndexPurpose.ExactMatch);
        var phone = provider.CreateIndex("max@example.com", Context(property: "Phone"), BlindIndexPurpose.ExactMatch);

        Assert.NotEqual(email, phone);
    }

    [Fact]
    public void CreateIndex_DiffersByValue()
    {
        var provider = Provider();
        var context = Context();

        var a = provider.CreateIndex("max@example.com", context, BlindIndexPurpose.ExactMatch);
        var b = provider.CreateIndex("eva@example.com", context, BlindIndexPurpose.ExactMatch);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Index_UsesBlindIndexPurposeKey_NotEncryptionPurposeKey()
    {
        var keyProvider = new LocalDevelopmentKeyProvider(RootKey);
        var provider = new HmacBlindIndexProvider(keyProvider);
        var context = Context();
        var valueBytes = Encoding.UTF8.GetBytes("max@example.com");

        var index = provider.Compute(valueBytes, BlindIndexDescriptor.ExactMatch, context);

        // The same value HMACed under the encryption-purpose key must give a different result,
        // proving the index is bound to the blind-index purpose.
        var keyId = keyProvider.GetCurrentKeyId(context.Tenant);
        var encryptionKey = keyProvider.DeriveKey(context.Tenant, new KeyDescriptor(keyId, KeyPurpose.Encryption, context.Scope));
        var hmacWithEncryptionKey = HMACSHA256.HashData(encryptionKey, valueBytes);

        Assert.NotEqual(hmacWithEncryptionKey, index.ToArray());
    }

    [Fact]
    public void EmailNormalizer_IsCaseInsensitiveAndTrimmed()
    {
        var provider = Provider();
        var context = Context();

        var canonical = provider.CreateIndex("max@example.com", context, BlindIndexPurpose.ExactMatch, EmailBlindIndexNormalizer.Instance);
        var mixedCase = provider.CreateIndex("  Max@Example.COM  ", context, BlindIndexPurpose.ExactMatch, EmailBlindIndexNormalizer.Instance);

        Assert.Equal(canonical, mixedCase);
    }

    [Fact]
    public void DefaultNormalizer_TrimsButIsCaseSensitive()
    {
        var provider = Provider();
        var context = Context();

        var lower = provider.CreateIndex("value", context, BlindIndexPurpose.ExactMatch);
        var padded = provider.CreateIndex("  value  ", context, BlindIndexPurpose.ExactMatch);
        var upper = provider.CreateIndex("VALUE", context, BlindIndexPurpose.ExactMatch);

        Assert.Equal(lower, padded);
        Assert.NotEqual(lower, upper);
    }
}

public sealed class HmacBlindIndexSecurityTests
{
    private static readonly byte[] RootKey = Enumerable.Range(0, 32).Select(i => (byte)(i + 1)).ToArray();

    private static EncryptionContext Context() =>
        new(new TenantId("acme"), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));

    private static HmacBlindIndexProvider Provider() => new(new LocalDevelopmentKeyProvider(RootKey));

    [Fact]
    public void Index_IsFull32Bytes()
    {
        var index = Provider().CreateIndex("max@example.com", Context(), BlindIndexPurpose.ExactMatch);

        Assert.Equal(32, index.Length);
    }

    [Fact]
    public void Index_IsNotEqualToPlaintext()
    {
        const string value = "max@example.com";
        var index = Provider().CreateIndex(value, Context(), BlindIndexPurpose.ExactMatch);

        Assert.NotEqual(Encoding.UTF8.GetBytes(value), index.ToArray());
    }

    [Fact]
    public void CreateIndex_RejectsNullValue()
    {
        Assert.Throws<ArgumentNullException>(() => Provider().CreateIndex(null!, Context(), BlindIndexPurpose.ExactMatch));
    }

    [Fact]
    public void CreateIndex_RejectsNullNormalizer()
    {
        Assert.Throws<ArgumentNullException>(() => Provider().CreateIndex("x", Context(), BlindIndexPurpose.ExactMatch, null!));
    }

    [Fact]
    public void Compute_RejectsNullDescriptorAndContext()
    {
        var provider = Provider();
        Assert.Throws<ArgumentNullException>(() => provider.Compute("x"u8, null!, Context()));
        Assert.Throws<ArgumentNullException>(() => provider.Compute("x"u8, BlindIndexDescriptor.ExactMatch, null!));
    }

    [Fact]
    public void Constructor_RejectsNullKeyProvider()
    {
        Assert.Throws<ArgumentNullException>(() => new HmacBlindIndexProvider(null!));
    }
}
