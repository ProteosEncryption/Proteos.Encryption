using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Search;

public sealed class RotationAwareBlindIndexTests
{
    private static readonly byte[] R1 = Enumerable.Repeat((byte)0x11, 32).ToArray();
    private static readonly byte[] R2 = Enumerable.Repeat((byte)0x22, 32).ToArray();
    private static readonly byte[] R3 = Enumerable.Repeat((byte)0x33, 32).ToArray();
    private static readonly byte[] Value = "max@example.com"u8.ToArray();

    private static LocalDevelopmentKeyVersion V(ushort version, byte[] rootKey) => new(version, rootKey);

    private static EncryptionContext Context() =>
        new(new TenantId("acme"), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));

    [Fact]
    public void ComputeForAllKnownKeys_ReturnsOneDistinctIndexPerVersion()
    {
        var blindIndex = new HmacBlindIndexProvider(LocalDevelopmentKeyProvider.CreateRotating([V(1, R1), V(2, R2), V(3, R3)], 3));

        var all = blindIndex.ComputeForAllKnownKeys(Value, BlindIndexDescriptor.ExactMatch, Context());

        Assert.Equal(3, all.Count);
        Assert.Equal(3, all.Distinct().Count()); // different version keys -> different index values
    }

    [Fact]
    public void ComputeForAllKnownKeys_IncludesTheIndexEachVersionWroteWithItsOwnCurrentKey()
    {
        var context = Context();
        var writtenUnderV1 = new HmacBlindIndexProvider(LocalDevelopmentKeyProvider.CreateRotating([V(1, R1)], 1))
            .Compute(Value, BlindIndexDescriptor.ExactMatch, context);
        var writtenUnderV2 = new HmacBlindIndexProvider(LocalDevelopmentKeyProvider.CreateRotating([V(1, R1), V(2, R2)], 2))
            .Compute(Value, BlindIndexDescriptor.ExactMatch, context);

        var searchTerms = new HmacBlindIndexProvider(LocalDevelopmentKeyProvider.CreateRotating([V(1, R1), V(2, R2), V(3, R3)], 3))
            .ComputeForAllKnownKeys(Value, BlindIndexDescriptor.ExactMatch, context);

        Assert.Contains(writtenUnderV1, searchTerms);
        Assert.Contains(writtenUnderV2, searchTerms);
    }

    [Fact]
    public void ComputeForAllKnownKeys_SingleVersionProvider_ReturnsExactlyTheCurrentKeyIndex()
    {
        var context = Context();
        var blindIndex = new HmacBlindIndexProvider(new LocalDevelopmentKeyProvider(R1)); // single version

        var current = blindIndex.Compute(Value, BlindIndexDescriptor.ExactMatch, context);
        var all = blindIndex.ComputeForAllKnownKeys(Value, BlindIndexDescriptor.ExactMatch, context);

        Assert.Equal(new[] { current }, all);
    }

    [Fact]
    public void GetKnownKeyIds_DefaultInterfaceImplementation_ReturnsCurrentOnly()
    {
        // A provider that does not override GetKnownKeyIds falls back to the current key id only.
        var tenant = new TenantId("acme");
        IKeyMaterialProvider provider = new CurrentOnlyKeyProvider();

        var known = provider.GetKnownKeyIds(tenant);

        Assert.Equal(new[] { provider.GetCurrentKeyId(tenant) }, known);
    }

    // Minimal provider that intentionally does NOT override GetKnownKeyIds, to exercise the default.
    private sealed class CurrentOnlyKeyProvider : IKeyMaterialProvider
    {
        private readonly LocalDevelopmentKeyProvider _inner = new(R1);

        public string ProviderId => "current-only-stub";

        public KeyId GetCurrentKeyId(TenantId tenant) => _inner.GetCurrentKeyId(tenant);

        public byte[] DeriveKey(TenantId tenant, KeyDescriptor descriptor) => _inner.DeriveKey(tenant, descriptor);
    }
}
