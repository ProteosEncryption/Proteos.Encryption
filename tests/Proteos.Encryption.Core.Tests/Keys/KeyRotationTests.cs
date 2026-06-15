using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Keys;

public sealed class KeyRotationTests
{
    private static readonly byte[] RootV1 = Enumerable.Repeat((byte)0x11, 32).ToArray();
    private static readonly byte[] RootV2 = Enumerable.Repeat((byte)0x22, 32).ToArray();
    private static readonly byte[] RootV3 = Enumerable.Repeat((byte)0x33, 32).ToArray();

    private static LocalDevelopmentKeyVersion V(ushort version, byte[] rootKey) => new(version, rootKey);

    private static EncryptionContext Context(string tenant = "acme") =>
        new(new TenantId(tenant), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));

    private static AesGcmValueEncryptionService Service(LocalDevelopmentKeyProvider provider) =>
        new(provider, new CiphertextEnvelopeCodec());

    private static int KeyVersionOf(byte[] envelopeBytes)
    {
        var keyId = new CiphertextEnvelopeCodec().Parse(envelopeBytes).Header.KeyId.Span;
        return (keyId[keyId.Length - 2] << 8) | keyId[keyId.Length - 1];
    }

    [Fact]
    public void Rotation_OldDataStaysDecryptable_NewDataUsesCurrentVersion()
    {
        var context = Context();
        var underV1 = "written under v1"u8.ToArray();
        var underV2 = "written under v2"u8.ToArray();

        // Phase 1 — current is v1.
        var beforeRotation = LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1)], currentVersion: 1);
        var envelopeFromV1 = Service(beforeRotation).EncryptToBytes(underV1, context);

        // Phase 2 — rotate: keep v1, add v2, current becomes v2.
        var afterRotation = LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2)], currentVersion: 2);
        var service = Service(afterRotation);
        var envelopeFromV2 = service.EncryptToBytes(underV2, context);

        Assert.Equal(1, KeyVersionOf(envelopeFromV1));
        Assert.Equal(2, KeyVersionOf(envelopeFromV2)); // new data uses the current version

        Assert.Equal(underV1, service.DecryptFromBytes(envelopeFromV1, context)); // old data still readable
        Assert.Equal(underV2, service.DecryptFromBytes(envelopeFromV2, context));
    }

    [Fact]
    public void MultipleVersions_AllRemainDecryptable_UnderOneCurrentProvider()
    {
        var context = Context();
        var p1 = "one"u8.ToArray();
        var p2 = "two"u8.ToArray();
        var p3 = "three"u8.ToArray();

        var e1 = Service(LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1)], 1)).EncryptToBytes(p1, context);
        var e2 = Service(LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2)], 2)).EncryptToBytes(p2, context);
        var e3 = Service(LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2), V(3, RootV3)], 3)).EncryptToBytes(p3, context);

        var allVersions = LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2), V(3, RootV3)], 3);
        var service = Service(allVersions);

        Assert.Equal(p1, service.DecryptFromBytes(e1, context));
        Assert.Equal(p2, service.DecryptFromBytes(e2, context));
        Assert.Equal(p3, service.DecryptFromBytes(e3, context));
        Assert.Equal(new ushort[] { 1, 2, 3 }, allVersions.KnownVersions);
        Assert.Equal(3, allVersions.CurrentVersion);
    }

    [Fact]
    public void DifferentVersions_ProduceDifferentKeyIdsAndDerivedKeys()
    {
        var tenant = new TenantId("acme");
        var scope = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"));
        var atV1 = LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2)], 1);
        var atV2 = LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2)], 2);

        var keyIdV1 = atV1.GetCurrentKeyId(tenant);
        var keyIdV2 = atV2.GetCurrentKeyId(tenant);
        Assert.NotEqual(keyIdV1, keyIdV2);

        var keyV1 = atV1.DeriveKey(tenant, new KeyDescriptor(keyIdV1, KeyPurpose.Encryption, scope));
        var keyV2 = atV2.DeriveKey(tenant, new KeyDescriptor(keyIdV2, KeyPurpose.Encryption, scope));
        Assert.NotEqual(keyV1, keyV2);
    }

    [Fact]
    public void UnknownKeyVersion_FailsToDecrypt()
    {
        var context = Context();
        var envelopeFromV2 = Service(LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2)], 2))
            .EncryptToBytes("secret"u8.ToArray(), context);

        var onlyV1 = Service(LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1)], 1));

        Assert.Throws<KeyResolutionException>(() => onlyV1.DecryptFromBytes(envelopeFromV2, context));
    }

    [Fact]
    public void CreateRotating_WithCurrentVersionNotProvided_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(2, RootV2)], currentVersion: 5));
    }

    [Fact]
    public void CreateRotating_WithDuplicateVersion_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1), V(1, RootV2)], currentVersion: 1));
    }

    [Fact]
    public void CreateRotating_WithNoVersions_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            LocalDevelopmentKeyProvider.CreateRotating([], currentVersion: 1));
    }

    [Fact]
    public void SingleVersionRotatingProvider_IsByteIdenticalToLegacyProvider()
    {
        var tenant = new TenantId("acme");
        var scope = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"));
        var legacy = new LocalDevelopmentKeyProvider(RootV1);
        var rotating = LocalDevelopmentKeyProvider.CreateRotating([V(1, RootV1)], currentVersion: 1);

        var legacyKeyId = legacy.GetCurrentKeyId(tenant);
        var rotatingKeyId = rotating.GetCurrentKeyId(tenant);
        Assert.Equal(legacyKeyId, rotatingKeyId);
        Assert.Equal(18, rotatingKeyId.Length); // envelope key id layout unchanged
        Assert.Equal((ushort)1, rotating.CurrentVersion);

        var legacyKey = legacy.DeriveKey(tenant, new KeyDescriptor(legacyKeyId, KeyPurpose.Encryption, scope));
        var rotatingKey = rotating.DeriveKey(tenant, new KeyDescriptor(rotatingKeyId, KeyPurpose.Encryption, scope));
        Assert.Equal(legacyKey, rotatingKey);
    }
}
