using System.Reflection;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests;

public sealed class AttributeTests
{
    [Fact]
    public void EncryptedEntity_CanBeRead()
    {
        var attribute = typeof(ValidCustomer).GetCustomAttribute<EncryptedEntityAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal("customer", attribute!.Name);
    }

    [Fact]
    public void Encrypted_CanBeRead()
    {
        var attribute = typeof(ValidCustomer).GetProperty(nameof(ValidCustomer.Phone))!
            .GetCustomAttribute<EncryptedAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal("phone", attribute!.Name);
        Assert.IsType<EncryptedAttribute>(attribute);
    }

    [Fact]
    public void EncryptedEmail_CanBeRead_AndIsSearchableWithEmailNormalizer()
    {
        var attribute = typeof(ValidCustomer).GetProperty(nameof(ValidCustomer.Email))!
            .GetCustomAttribute<EncryptedEmailAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal("email", attribute!.Name);
        Assert.Equal(BlindIndexNormalizerKind.Email, attribute.Normalizer);
        Assert.Null(attribute.IndexProperty);
        Assert.IsAssignableFrom<EncryptedSearchableAttribute>(attribute);
    }

    [Fact]
    public void EncryptedEmail_IsAnEncryptedAttribute_AndFoundAsOne()
    {
        var asEncrypted = typeof(ValidCustomer).GetProperty(nameof(ValidCustomer.Email))!
            .GetCustomAttribute<EncryptedAttribute>();

        Assert.IsType<EncryptedEmailAttribute>(asEncrypted);
    }

    [Fact]
    public void EncryptedSearchable_Normalizer_DefaultsToDefault()
    {
        Assert.Equal(BlindIndexNormalizerKind.Default, new EncryptedSearchableAttribute("x").Normalizer);
    }

    [Fact]
    public void EncryptedEmail_Normalizer_IsEmail()
    {
        Assert.Equal(BlindIndexNormalizerKind.Email, new EncryptedEmailAttribute("x").Normalizer);
    }
}
