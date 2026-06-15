using Proteos.Encryption.Abstractions;
using Xunit;

namespace Proteos.Encryption.Abstractions.Tests;

public sealed class CiphertextEnvelopeFormatTests
{
    [Fact]
    public void Magic_IsPencFourBytes()
    {
        Assert.Equal(4, CiphertextEnvelopeFormat.MagicLength);
        Assert.Equal(new byte[] { 0x50, 0x45, 0x4E, 0x43 }, CiphertextEnvelopeFormat.Magic.ToArray());
        Assert.Equal("PENC", System.Text.Encoding.ASCII.GetString(CiphertextEnvelopeFormat.GetMagic()));
    }

    [Fact]
    public void GetMagic_ReturnsDefensiveCopy()
    {
        var magic = CiphertextEnvelopeFormat.GetMagic();
        magic[0] = 0xFF;

        Assert.Equal(new byte[] { 0x50, 0x45, 0x4E, 0x43 }, CiphertextEnvelopeFormat.Magic.ToArray());
    }

    [Fact]
    public void StartsWithMagic_RecognisesPrefix()
    {
        Assert.True(CiphertextEnvelopeFormat.StartsWithMagic([0x50, 0x45, 0x4E, 0x43, 0x01]));
        Assert.False(CiphertextEnvelopeFormat.StartsWithMagic([0x50, 0x45, 0x4E, 0x00]));
        Assert.False(CiphertextEnvelopeFormat.StartsWithMagic([0x50, 0x45, 0x4E]));
        Assert.False(CiphertextEnvelopeFormat.StartsWithMagic(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void CurrentVersion_IsV1()
    {
        Assert.Equal(EnvelopeVersion.V1, CiphertextEnvelopeFormat.CurrentVersion);
    }

    [Fact]
    public void FieldWidths_AreStable()
    {
        Assert.Equal(1, CiphertextEnvelopeFormat.VersionFieldLength);
        Assert.Equal(1, CiphertextEnvelopeFormat.CryptoSuiteIdFieldLength);
        Assert.Equal(1, CiphertextEnvelopeFormat.AadSchemeIdFieldLength);
        Assert.Equal(1, CiphertextEnvelopeFormat.KeyIdLengthFieldLength);
        Assert.Equal(1, CiphertextEnvelopeFormat.NonceLengthFieldLength);
        Assert.Equal(1, CiphertextEnvelopeFormat.TagLengthFieldLength);
        Assert.Equal(4, CiphertextEnvelopeFormat.CiphertextLengthFieldLength);
    }

    [Fact]
    public void LengthFields_AreBigEndian()
    {
        Assert.Equal(EnvelopeByteOrder.BigEndian, CiphertextEnvelopeFormat.LengthFieldByteOrder);
    }

    [Fact]
    public void DerivedSizes_AreConsistentWithLayout()
    {
        // 4 magic + 1 version + 1 suite + 1 aadScheme + 1 keyIdLen + 1 nonceLen + 1 tagLen + 4 ctLen
        Assert.Equal(14, CiphertextEnvelopeFormat.FixedOverheadLength);

        // 14 overhead + 1 keyId + 1 nonce + 1 tag + 0 ciphertext
        Assert.Equal(17, CiphertextEnvelopeFormat.MinimumEnvelopeLength);
    }

    [Fact]
    public void HeaderAadComponents_AreHeaderFieldsInOrder()
    {
        Assert.Equal(
            new[]
            {
                EnvelopeAadComponent.Version,
                EnvelopeAadComponent.CryptoSuiteId,
                EnvelopeAadComponent.AadSchemeId,
                EnvelopeAadComponent.KeyId,
            },
            CiphertextEnvelopeFormat.HeaderAadComponents);
    }

    [Fact]
    public void HeaderAadComponents_BindKeyIdButNotFramingFields()
    {
        Assert.Contains(EnvelopeAadComponent.KeyId, CiphertextEnvelopeFormat.HeaderAadComponents);

        // The magic marker and the length prefixes are framing only: there is no enum member for
        // them, and the AAD is exactly the four header fields.
        Assert.Equal(4, CiphertextEnvelopeFormat.HeaderAadComponents.Count);
        Assert.False(Enum.IsDefined((EnvelopeAadComponent)0));
    }

    [Fact]
    public void IsSupportedVersion_OnlyAcceptsV1()
    {
        Assert.True(CiphertextEnvelopeFormat.IsSupportedVersion(EnvelopeVersion.V1));
        Assert.False(CiphertextEnvelopeFormat.IsSupportedVersion(new EnvelopeVersion(0x02)));
        Assert.False(CiphertextEnvelopeFormat.IsSupportedVersion(default));
    }

    [Fact]
    public void SuiteClassification_SeparatesSupportedKnownAndUnknown()
    {
        Assert.True(CiphertextEnvelopeFormat.IsSupportedSuite(CryptoSuiteId.Aes256Gcm));
        Assert.False(CiphertextEnvelopeFormat.IsSupportedSuite(CryptoSuiteId.XChaCha20Poly1305));

        Assert.True(CiphertextEnvelopeFormat.IsKnownSuite(CryptoSuiteId.XChaCha20Poly1305));
        Assert.False(CiphertextEnvelopeFormat.IsKnownSuite(new CryptoSuiteId(0x7F)));
        Assert.False(CiphertextEnvelopeFormat.IsSupportedSuite(default));
    }

    [Fact]
    public void AadSchemeClassification_SeparatesSupportedKnownAndUnknown()
    {
        Assert.True(CiphertextEnvelopeFormat.IsSupportedAadScheme(AadSchemeId.HeaderBound));
        Assert.False(CiphertextEnvelopeFormat.IsSupportedAadScheme(AadSchemeId.ContextBound));

        Assert.True(CiphertextEnvelopeFormat.IsKnownAadScheme(AadSchemeId.ContextBound));
        Assert.False(CiphertextEnvelopeFormat.IsKnownAadScheme(new AadSchemeId(0x7F)));
        Assert.False(CiphertextEnvelopeFormat.IsSupportedAadScheme(default));
    }
}

public sealed class CiphertextEnvelopeLimitsTests
{
    [Fact]
    public void KeyIdBounds_Are1To255_AndMatchTheKeyIdValueObject()
    {
        Assert.Equal(1, CiphertextEnvelopeLimits.KeyIdMinLength);
        Assert.Equal(255, CiphertextEnvelopeLimits.KeyIdMaxLength);
        Assert.Equal(KeyId.MinLength, CiphertextEnvelopeLimits.KeyIdMinLength);
        Assert.Equal(KeyId.MaxLength, CiphertextEnvelopeLimits.KeyIdMaxLength);
    }

    [Fact]
    public void NonceAndTagBounds_Are1To255()
    {
        Assert.Equal(1, CiphertextEnvelopeLimits.NonceMinLength);
        Assert.Equal(255, CiphertextEnvelopeLimits.NonceMaxLength);
        Assert.Equal(1, CiphertextEnvelopeLimits.TagMinLength);
        Assert.Equal(255, CiphertextEnvelopeLimits.TagMaxLength);
    }

    [Fact]
    public void CiphertextBounds_AllowEmptyAndUpToUInt32Max()
    {
        Assert.Equal(0u, CiphertextEnvelopeLimits.CiphertextMinLength);
        Assert.Equal(uint.MaxValue, CiphertextEnvelopeLimits.CiphertextMaxLength);
        Assert.Equal(4_294_967_295u, CiphertextEnvelopeLimits.CiphertextMaxLength);
    }
}

public sealed class CryptoSuiteRegistryTests
{
    [Fact]
    public void Aes256Gcm_IsImplementedWithGcmSizes()
    {
        var gcm = CryptoSuiteRegistry.Aes256Gcm;

        Assert.Equal(CryptoSuiteId.Aes256Gcm, gcm.Id);
        Assert.True(gcm.IsImplemented);
        Assert.Equal(12, gcm.NonceLength);
        Assert.Equal(16, gcm.TagLength);
    }

    [Fact]
    public void ReservedSuites_AreKnownButNotImplemented()
    {
        foreach (var reserved in new[]
                 {
                     CryptoSuiteRegistry.Aes256GcmSiv,
                     CryptoSuiteRegistry.XChaCha20Poly1305,
                     CryptoSuiteRegistry.Aes256SivDeterministic,
                 })
        {
            Assert.False(reserved.IsImplemented);
            Assert.Equal(0, reserved.NonceLength);
            Assert.Equal(0, reserved.TagLength);
            Assert.True(CryptoSuiteRegistry.IsKnown(reserved.Id));
        }
    }

    [Fact]
    public void Registry_ContainsExactlyTheFourRegisteredSuites()
    {
        Assert.Equal(4, CryptoSuiteRegistry.All.Count);
        Assert.Contains(CryptoSuiteRegistry.All, s => s.Id == CryptoSuiteId.Aes256Gcm);
        Assert.Contains(CryptoSuiteRegistry.All, s => s.Id == CryptoSuiteId.Aes256GcmSiv);
        Assert.Contains(CryptoSuiteRegistry.All, s => s.Id == CryptoSuiteId.XChaCha20Poly1305);
        Assert.Contains(CryptoSuiteRegistry.All, s => s.Id == CryptoSuiteId.Aes256SivDeterministic);
    }

    [Fact]
    public void TryGet_ReturnsFalseForUnknownId()
    {
        Assert.False(CryptoSuiteRegistry.TryGet(new CryptoSuiteId(0x7F), out var definition));
        Assert.Null(definition);
    }

    [Fact]
    public void Get_ThrowsForUnknownId()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoSuiteRegistry.Get(new CryptoSuiteId(0x7F)));
    }
}

public sealed class CryptoSuiteDefinitionTests
{
    [Fact]
    public void Constructor_RejectsImplementedSuiteWithOutOfRangeNonce()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CryptoSuiteDefinition(CryptoSuiteId.Aes256Gcm, "x", isImplemented: true, nonceLength: 0, tagLength: 16));
    }

    [Fact]
    public void Constructor_RejectsImplementedSuiteWithOutOfRangeTag()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CryptoSuiteDefinition(CryptoSuiteId.Aes256Gcm, "x", isImplemented: true, nonceLength: 12, tagLength: 256));
    }

    [Fact]
    public void Constructor_RejectsReservedSuiteWithNonZeroSizes()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CryptoSuiteDefinition(CryptoSuiteId.XChaCha20Poly1305, "x", isImplemented: false, nonceLength: 24, tagLength: 16));
    }

    [Fact]
    public void Constructor_RejectsEmptyName()
    {
        Assert.Throws<ArgumentException>(() =>
            new CryptoSuiteDefinition(CryptoSuiteId.Aes256Gcm, "  ", isImplemented: true, nonceLength: 12, tagLength: 16));
    }
}
