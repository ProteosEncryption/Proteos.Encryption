using Proteos.Encryption.Abstractions;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests;

public sealed class EncryptedEntityMetadataScannerTests
{
    private static EncryptedPropertyDescriptor Property(Type entityType, string name) =>
        EncryptedEntityMetadataScanner.Scan(entityType).Properties.Single(p => p.PropertyName == name);

    [Fact]
    public void Scan_ReadsEntityLogicalName_AndFindsEncryptedProperties()
    {
        var metadata = EncryptedEntityMetadataScanner.Scan(typeof(ValidCustomer));

        Assert.Equal("customer", metadata.EntityLogicalName);
        Assert.True(metadata.HasEncryptedProperties);
        Assert.Equal(
            new[] { "Email", "Phone", "Ssn" },
            metadata.Properties.Select(p => p.PropertyName).OrderBy(n => n).ToArray());
    }

    [Fact]
    public void Scan_BuildsScopeFromEntityAndPropertyLogicalNames()
    {
        var email = Property(typeof(ValidCustomer), "Email");

        Assert.Equal("email", email.PropertyLogicalName);
        Assert.Equal(new EncryptedDataScope(new LogicalName("customer"), new LogicalName("email")), email.Scope);
    }

    [Fact]
    public void Scan_SearchableProperty_HasShadowIndexByDefault()
    {
        var email = Property(typeof(ValidCustomer), "Email");

        Assert.True(email.IsSearchable);
        Assert.Equal("EmailIndex", email.IndexPropertyName);
        Assert.True(email.IndexIsShadow);
        Assert.Equal(BlindIndexNormalizerKind.Email, email.NormalizerKind);
    }

    [Fact]
    public void Scan_EncryptedOnlyProperty_HasNoIndex()
    {
        var phone = Property(typeof(ValidCustomer), "Phone");

        Assert.False(phone.IsSearchable);
        Assert.Null(phone.IndexPropertyName);
        Assert.False(phone.IndexIsShadow);
        Assert.Null(phone.NormalizerKind);
    }

    [Fact]
    public void Scan_ByteArrayProperty_IsSupported()
    {
        var ssn = Property(typeof(ValidCustomer), "Ssn");

        Assert.Equal(typeof(byte[]), ssn.PropertyType);
        Assert.False(ssn.IsSearchable);
    }

    [Fact]
    public void Scan_ExplicitIndexProperty_IsNotShadow()
    {
        var email = Property(typeof(CustomerWithExplicitIndex), "Email");

        Assert.True(email.IsSearchable);
        Assert.Equal("EmailIndex", email.IndexPropertyName);
        Assert.False(email.IndexIsShadow);
    }

    [Fact]
    public void Scan_EntityWithoutEncryptedProperties_IsEmpty()
    {
        var metadata = EncryptedEntityMetadataScanner.Scan(typeof(PlainEntity));

        Assert.False(metadata.HasEncryptedProperties);
        Assert.Empty(metadata.Properties);
    }

    [Fact]
    public void Scan_MultipleProperties_AreAllRecognised()
    {
        var metadata = EncryptedEntityMetadataScanner.Scan(typeof(CustomerMultiple));

        Assert.Equal(4, metadata.Properties.Count);
        Assert.Equal(2, metadata.Properties.Count(p => p.IsSearchable));
    }

    [Fact]
    public void Scan_IsStable_AcrossRepeatedCalls()
    {
        var first = EncryptedEntityMetadataScanner.Scan(typeof(ValidCustomer));
        var second = EncryptedEntityMetadataScanner.Scan(typeof(ValidCustomer));

        Assert.Equal(first.Properties, second.Properties);
    }

    [Fact]
    public void Scan_WithNullType_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => EncryptedEntityMetadataScanner.Scan(null!));
    }
}
