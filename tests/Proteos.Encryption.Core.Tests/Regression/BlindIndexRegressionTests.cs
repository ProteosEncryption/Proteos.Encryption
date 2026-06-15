using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// Golden regression for the blind index. The expected 32-byte index below is OUR OWN golden
/// value, captured once from the implementation — it is not an external standard. It pins the
/// whole chain (index-key derivation, normalization and HMAC-SHA256) so an accidental change to
/// the HKDF info structure, the normalizer or the HMAC breaks this test.
/// </summary>
public sealed class BlindIndexRegressionTests
{
    private const string RootKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    private const string ExpectedIndexHex = "158663ef174e8860c6f4f6965f5ec8b91eccde061ce9478219d39df9f7d95f7b";

    private static readonly TenantId Tenant = new("tenant-a");

    private static EncryptionContext Context() =>
        new(Tenant, new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));

    [Fact]
    public void EmailIndex_WithFixedInputs_MatchesGolden()
    {
        var provider = new HmacBlindIndexProvider(new LocalDevelopmentKeyProvider(Hex.FromHex(RootKeyHex)));

        var index = provider.CreateIndex("max@example.com", Context(), BlindIndexPurpose.ExactMatch, EmailBlindIndexNormalizer.Instance);

        Assert.Equal(ExpectedIndexHex, Hex.ToHex(index.Span));
    }
}
