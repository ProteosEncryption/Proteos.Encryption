using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Keys;

public sealed class RegistryKeyMaterialProviderTests
{
    private const KeyProviderKind Kind = KeyProviderKind.AzureKeyVault;

    private static readonly Guid Tmk = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static readonly TenantId Tenant = new("acme");
    private static readonly InMemoryKeyProvider Kek = new(0x5A);

    private static EncryptedDataScope Scope() => new(new LogicalName("Customer"), new LogicalName("Email"));

    private static EncryptionContext Context() => new(Tenant, Scope());

    private static byte[] Tmk32(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    private static KeyId KeyIdOf(ushort version)
    {
        var bytes = new byte[18];
        Tmk.ToByteArray().CopyTo(bytes, 0);
        bytes[16] = (byte)(version >> 8);
        bytes[17] = (byte)version;
        return KeyId.FromBytes(bytes);
    }

    private static TenantKeyVersion WrappedVersion(ushort version, byte fill, IKeyProvider kek, KeyProviderKind kind = Kind)
    {
        var wrapped = kek.WrapAsync(KeyIdOf(version), Tmk32(fill)).AsTask().GetAwaiter().GetResult();
        return new TenantKeyVersion(version, new ProviderKeyReference(kind, $"ref-v{version}"), wrapped);
    }

    private static TenantKeyRecord Record(ushort current, params TenantKeyVersion[] versions) => new(Tenant, Tmk, versions, current);

    private static RegistryKeyMaterialProvider Provider(TenantKeyRecord record, IKeyProvider? kek = null) =>
        new(new InMemoryTenantKeyRegistry([record]), Kind, kek ?? Kek);

    private static KeyDescriptor Descriptor(KeyId keyId) => new(keyId, KeyPurpose.Encryption, Scope());

    [Fact]
    public void GetCurrentKeyId_ReturnsRecordCurrent()
    {
        var record = Record(2, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek), WrappedVersion(3, 3, Kek));

        Assert.Equal(record.CurrentKeyId, Provider(record).GetCurrentKeyId(Tenant));
    }

    [Fact]
    public void GetKnownKeyIds_ReturnsAllVersions()
    {
        var record = Record(3, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek), WrappedVersion(3, 3, Kek));
        var known = Provider(record).GetKnownKeyIds(Tenant);

        Assert.Equal(record.GetKnownKeyIds(), known);
        Assert.Equal(3, known.Count);
    }

    [Fact]
    public void DeriveKey_CurrentVersion_ReturnsWorkingKey()
    {
        var record = Record(2, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek));
        var provider = Provider(record);

        Assert.Equal(32, provider.DeriveKey(Tenant, Descriptor(provider.GetCurrentKeyId(Tenant))).Length);
    }

    [Fact]
    public void DeriveKey_OldVersion_ReturnsWorkingKey()
    {
        var record = Record(3, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek), WrappedVersion(3, 3, Kek));

        Assert.Equal(32, Provider(record).DeriveKey(Tenant, Descriptor(record.KeyIdFor(1))).Length);
    }

    [Fact]
    public void DeriveKey_DifferentVersions_ProduceDifferentWorkingKeys()
    {
        var record = Record(2, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek));
        var provider = Provider(record);

        var v1 = provider.DeriveKey(Tenant, Descriptor(record.KeyIdFor(1)));
        var v2 = provider.DeriveKey(Tenant, Descriptor(record.KeyIdFor(2)));

        Assert.NotEqual(v1, v2);
    }

    [Fact]
    public void DeriveKey_UnknownTenant_Throws()
    {
        var record = Record(1, WrappedVersion(1, 1, Kek));

        Assert.Throws<KeyResolutionException>(() =>
            Provider(record).DeriveKey(new TenantId("globex"), Descriptor(record.CurrentKeyId)));
    }

    [Fact]
    public void DeriveKey_UnknownKeyId_Throws()
    {
        var record = Record(1, WrappedVersion(1, 1, Kek));
        var foreign = KeyId.FromBytes(Enumerable.Repeat((byte)0xCC, 18).ToArray());

        Assert.Throws<KeyResolutionException>(() => Provider(record).DeriveKey(Tenant, Descriptor(foreign)));
    }

    [Fact]
    public void DeriveKey_VersionWithoutWrappedKey_Throws()
    {
        var record = Record(1, new TenantKeyVersion(1, new ProviderKeyReference(Kind, "ref-v1"))); // no wrapped TMK

        Assert.Throws<KeyResolutionException>(() => Provider(record).DeriveKey(Tenant, Descriptor(record.CurrentKeyId)));
    }

    [Fact]
    public void DeriveKey_NoProviderForVersionKind_Throws()
    {
        var record = Record(1, WrappedVersion(1, 1, Kek, KeyProviderKind.AwsKms)); // version says AWS; provider serves Azure only

        Assert.Throws<KeyResolutionException>(() => Provider(record).DeriveKey(Tenant, Descriptor(record.CurrentKeyId)));
    }

    [Fact]
    public void DeriveKey_UnwrapFails_Throws()
    {
        var record = Record(1, WrappedVersion(1, 1, Kek)); // wrapped under Kek (0x5A)
        var wrongKek = new InMemoryKeyProvider(0x11);

        Assert.Throws<KeyResolutionException>(() => Provider(record, wrongKek).DeriveKey(Tenant, Descriptor(record.CurrentKeyId)));
    }

    [Fact]
    public void Integration_AesGcmService_EncryptsAndDecrypts()
    {
        var record = Record(2, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek));
        var service = new AesGcmValueEncryptionService(Provider(record), new CiphertextEnvelopeCodec());
        var context = Context();
        var plaintext = "max@example.com"u8.ToArray();

        var decrypted = service.DecryptFromBytes(service.EncryptToBytes(plaintext, context), context);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Integration_RotationAwareSearch_ComputesADistinctIndexPerVersion()
    {
        var record = Record(3, WrappedVersion(1, 1, Kek), WrappedVersion(2, 2, Kek), WrappedVersion(3, 3, Kek));
        var blindIndex = new HmacBlindIndexProvider(Provider(record));

        var all = blindIndex.ComputeForAllKnownKeys("max@example.com"u8.ToArray(), BlindIndexDescriptor.ExactMatch, Context());

        Assert.Equal(3, all.Count);
        Assert.Equal(3, all.Distinct().Count());
    }
}
