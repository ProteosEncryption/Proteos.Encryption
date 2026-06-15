using Proteos.Encryption.Abstractions;
using Xunit;

namespace Proteos.Encryption.Abstractions.Tests.Keys;

public sealed class TenantKeyModelTests
{
    private static readonly Guid Tmk = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static ProviderKeyReference Ref(int n) => new(KeyProviderKind.AzureKeyVault, $"https://vault.example/keys/key{n}");

    private static TenantKeyVersion V(ushort version, int n) => new(version, Ref(n));

    private static TenantKeyRecord Record(ushort current, params TenantKeyVersion[] versions) =>
        new(new TenantId("acme"), Tmk, versions, current);

    [Fact]
    public void Record_ExposesVersionsAscending_AndCurrent()
    {
        var record = Record(2, V(3, 3), V(1, 1), V(2, 2));

        Assert.Equal(new ushort[] { 1, 2, 3 }, record.Versions.Select(v => v.Version));
        Assert.Equal(2, record.CurrentVersion);
    }

    [Fact]
    public void KeyId_IsStableTmkIdPlusVersion()
    {
        var record = Record(3, V(1, 1), V(2, 2), V(3, 3));
        var tmkBytes = Tmk.ToByteArray();

        foreach (var version in record.Versions)
        {
            var keyId = record.KeyIdFor(version.Version).Span.ToArray();

            Assert.Equal(18, keyId.Length);                                 // envelope key id layout unchanged
            Assert.Equal(tmkBytes, keyId[..16]);                            // stable TmkId across versions
            Assert.Equal(version.Version, (ushort)((keyId[16] << 8) | keyId[17])); // version segment
        }
    }

    [Fact]
    public void CurrentKeyId_UsesCurrentVersion()
    {
        var record = Record(2, V(1, 1), V(2, 2), V(3, 3));

        Assert.Equal(record.KeyIdFor(2), record.CurrentKeyId);
    }

    [Fact]
    public void GetKnownKeyIds_ReturnsOnePerVersion()
    {
        var record = Record(3, V(1, 1), V(2, 2), V(3, 3));

        Assert.Equal(record.Versions.Select(v => record.KeyIdFor(v.Version)), record.GetKnownKeyIds());
        Assert.Equal(3, record.GetKnownKeyIds().Count);
    }

    [Fact]
    public void TryGetVersion_ResolvesAKeyIdBackToItsVersion()
    {
        var record = Record(3, V(1, 1), V(2, 2), V(3, 3));

        Assert.True(record.TryGetVersion(record.KeyIdFor(2), out var version));
        Assert.Equal(2, version!.Version);
    }

    [Fact]
    public void TryGetVersion_RejectsAForeignTmkId()
    {
        var record = Record(1, V(1, 1));

        Assert.False(record.TryGetVersion(KeyId.FromBytes(Enumerable.Repeat((byte)0xAB, 18).ToArray()), out _));
    }

    [Fact]
    public void TryGetVersion_RejectsAnUnknownVersionUnderTheSameTmkId()
    {
        var record = Record(1, V(1, 1));
        var bytes = new byte[18];
        Tmk.ToByteArray().CopyTo(bytes, 0);
        bytes[17] = 9; // version 9 — same TmkId, not in the record

        Assert.False(record.TryGetVersion(KeyId.FromBytes(bytes), out _));
    }

    [Fact]
    public void DuplicateVersions_AreRejected() =>
        Assert.Throws<ArgumentException>(() => Record(1, V(1, 1), V(1, 2)));

    [Fact]
    public void MissingCurrentVersion_IsRejected() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => Record(5, V(1, 1), V(2, 2)));

    [Fact]
    public void NoVersions_AreRejected() =>
        Assert.Throws<ArgumentException>(() => Record(1));

    [Fact]
    public void EmptyTmkId_IsRejected() =>
        Assert.Throws<ArgumentException>(() => new TenantKeyRecord(new TenantId("acme"), Guid.Empty, [V(1, 1)], 1));

    [Fact]
    public void ProviderKeyReference_RejectsEmptyReference() =>
        Assert.Throws<ArgumentException>(() => new ProviderKeyReference(KeyProviderKind.AwsKms, "   "));

    [Fact]
    public void ProviderKeyReference_RejectsUndefinedKind() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new ProviderKeyReference((KeyProviderKind)99, "arn:aws:kms:..."));

    [Fact]
    public void ProviderKeyReference_TrimsAndFormats()
    {
        var reference = new ProviderKeyReference(KeyProviderKind.GoogleKms, "  projects/p/locations/l/keyRings/r/cryptoKeys/k  ");

        Assert.Equal("projects/p/locations/l/keyRings/r/cryptoKeys/k", reference.Reference);
        Assert.Contains("GoogleKms", reference.ToString());
    }

    [Fact]
    public void TenantKeyVersion_RejectsVersionZero() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new TenantKeyVersion(0, Ref(1)));

    [Fact]
    public void TenantKeyVersion_RejectsNullReference() =>
        Assert.Throws<ArgumentNullException>(() => new TenantKeyVersion(1, null!));
}
