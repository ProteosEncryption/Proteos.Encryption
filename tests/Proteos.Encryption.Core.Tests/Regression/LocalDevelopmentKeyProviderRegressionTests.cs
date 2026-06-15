using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// Regression for the development provider's deterministic derivation. The expected key id and
/// derived key below are OUR OWN golden values, captured once from the implementation — they are
/// not externally standardised. They pin the HKDF info structure, labels and purpose tokens; a
/// change to any of those changes derived keys for existing data, and these tests catch that.
/// </summary>
public sealed class LocalDevelopmentKeyProviderRegressionTests
{
    private const string RootKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string ExpectedKeyIdHex = "77b23696f3269acd9e54dbf68613fad10001";
    private const string ExpectedDerivedKeyHex = "f41eb28526b3fcfa786e9ef6ecc1ae60a63a5b5c618c54e77672d32c107537b7";

    private static readonly TenantId Tenant = new("tenant-a");

    private static EncryptedDataScope Scope() => new(new LogicalName("Customer"), new LogicalName("Email"));

    private static LocalDevelopmentKeyProvider Provider() => new(Hex.FromHex(RootKeyHex));

    [Fact]
    public void GetCurrentKeyId_MatchesGolden()
    {
        Assert.Equal(ExpectedKeyIdHex, Hex.ToHex(Provider().GetCurrentKeyId(Tenant).Span));
    }

    [Fact]
    public void DeriveKey_Encryption_MatchesGolden()
    {
        var provider = Provider();
        var descriptor = new KeyDescriptor(provider.GetCurrentKeyId(Tenant), KeyPurpose.Encryption, Scope());

        Assert.Equal(ExpectedDerivedKeyHex, Hex.ToHex(provider.DeriveKey(Tenant, descriptor)));
    }
}
