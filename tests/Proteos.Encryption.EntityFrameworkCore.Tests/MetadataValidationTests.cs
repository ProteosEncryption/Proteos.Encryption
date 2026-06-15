using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests;

public sealed class MetadataValidationTests
{
    private static void AssertRejected<TEntity>() =>
        Assert.Throws<EncryptedEntityMetadataException>(() => EncryptedEntityMetadataScanner.Scan(typeof(TEntity)));

    [Fact]
    public void EncryptedWithoutEntityLogicalName_IsRejected() => AssertRejected<CustomerMissingEntityName>();

    [Fact]
    public void EmptyPropertyLogicalName_IsRejected() => AssertRejected<CustomerEmptyPropertyName>();

    [Fact]
    public void UnsupportedPropertyType_IsRejected() => AssertRejected<CustomerUnsupportedType>();

    [Fact]
    public void ReadOnlyProperty_IsRejected() => AssertRejected<CustomerReadOnlyProperty>();

    [Fact]
    public void WriteOnlyProperty_IsRejected() => AssertRejected<CustomerWriteOnlyProperty>();

    [Fact]
    public void SearchableOnNonString_IsRejected() => AssertRejected<CustomerSearchableNonString>();

    [Fact]
    public void ExplicitIndexPropertyWrongType_IsRejected() => AssertRejected<CustomerIndexWrongType>();

    [Fact]
    public void IndexPropertyPointingToSelf_IsRejected() => AssertRejected<CustomerIndexSelf>();

    [Fact]
    public void ShadowNameCollidesWithIncompatibleProperty_IsRejected() => AssertRejected<CustomerShadowCollision>();

    [Fact]
    public void DuplicateEncryptionAttributes_IsRejected() => AssertRejected<CustomerDuplicateAttributes>();

    [Fact]
    public void UnknownNormalizer_IsRejected() => AssertRejected<CustomerUnknownNormalizer>();
}

public sealed class BlindIndexNormalizerResolverTests
{
    [Fact]
    public void Resolve_Default_ReturnsDefaultNormalizer()
    {
        Assert.Same(DefaultBlindIndexNormalizer.Instance, BlindIndexNormalizerResolver.Resolve(BlindIndexNormalizerKind.Default));
    }

    [Fact]
    public void Resolve_Email_ReturnsEmailNormalizer()
    {
        Assert.Same(EmailBlindIndexNormalizer.Instance, BlindIndexNormalizerResolver.Resolve(BlindIndexNormalizerKind.Email));
    }

    [Fact]
    public void Resolve_UnknownKind_IsRejected()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() => BlindIndexNormalizerResolver.Resolve((BlindIndexNormalizerKind)99));
    }
}
