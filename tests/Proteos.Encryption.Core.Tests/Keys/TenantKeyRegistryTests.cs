using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Keys;

public sealed class TenantKeyRegistryTests
{
    private static readonly Guid Tmk1 = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Tmk2 = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private static ProviderKeyReference Ref() => new(KeyProviderKind.AzureKeyVault, "https://vault.example/keys/k");

    private static TenantKeyRecord Record(string tenant, Guid tmk, ushort current = 1, params ushort[] versions)
    {
        var keyVersions = (versions.Length == 0 ? [1] : versions).Select(v => new TenantKeyVersion(v, Ref())).ToArray();
        return new TenantKeyRecord(new TenantId(tenant), tmk, keyVersions, current);
    }

    [Fact]
    public void GetRecord_ReturnsTheRegisteredRecord()
    {
        var record = Record("acme", Tmk1);
        var registry = new InMemoryTenantKeyRegistry([record]);

        Assert.Same(record, registry.GetRecord(new TenantId("acme")));
    }

    [Fact]
    public void GetRecord_UnknownTenant_Throws()
    {
        var registry = new InMemoryTenantKeyRegistry([Record("acme", Tmk1)]);

        Assert.Throws<KeyResolutionException>(() => registry.GetRecord(new TenantId("globex")));
    }

    [Fact]
    public void DuplicateTenantRecords_AreRejected()
    {
        Assert.Throws<ArgumentException>(() => new InMemoryTenantKeyRegistry([Record("acme", Tmk1), Record("acme", Tmk2)]));
    }

    [Fact]
    public void MultipleTenants_ResolveIndependently()
    {
        var registry = new InMemoryTenantKeyRegistry([Record("acme", Tmk1), Record("globex", Tmk2)]);

        Assert.Equal(Tmk1, registry.GetRecord(new TenantId("acme")).TenantMasterKeyId);
        Assert.Equal(Tmk2, registry.GetRecord(new TenantId("globex")).TenantMasterKeyId);
    }

    [Fact]
    public void KeyIdFromRecord_RoundtripsThroughTheEnvelopeUnchanged()
    {
        // A KMS-shaped key id (stable TmkId ‖ version, 18 bytes) survives the existing envelope format.
        var keyId = Record("acme", Tmk1, current: 2, versions: [1, 2]).CurrentKeyId;
        var header = new CiphertextEnvelopeHeader(EnvelopeVersion.V1, CryptoSuiteId.Aes256Gcm, AadSchemeId.HeaderBound, keyId);
        var envelope = CiphertextEnvelope.Create(header, new byte[12], new byte[16], [1, 2, 3, 4]);
        var codec = new CiphertextEnvelopeCodec();

        var parsed = codec.Parse(codec.Serialize(envelope));

        Assert.Equal(keyId, parsed.Header.KeyId);
        Assert.Equal(18, parsed.Header.KeyId.Length);
    }
}
