using Proteos.Encryption.Abstractions;
using Xunit;

namespace Proteos.Encryption.Abstractions.Tests;

public sealed class TenantIdTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithNullEmptyOrWhitespace_IsRejected(string? value)
    {
        Assert.Throws<ArgumentException>(() => new TenantId(value!));
    }

    [Fact]
    public void Constructor_TrimsSurroundingWhitespace()
    {
        Assert.Equal("acme", new TenantId("  acme  ").Value);
    }

    [Fact]
    public void Equality_IsValueBased_AfterTrimming()
    {
        Assert.Equal(new TenantId("acme"), new TenantId(" acme "));
    }

    [Fact]
    public void Equality_DistinguishesDifferentTenants()
    {
        Assert.NotEqual(new TenantId("acme"), new TenantId("globex"));
    }
}

public sealed class LogicalNameTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithNullEmptyOrWhitespace_IsRejected(string? value)
    {
        Assert.Throws<ArgumentException>(() => new LogicalName(value!));
    }

    [Fact]
    public void Constructor_AboveMaxLength_IsRejected()
    {
        var tooLong = new string('a', LogicalName.MaxLength + 1);

        Assert.Throws<ArgumentException>(() => new LogicalName(tooLong));
    }

    [Fact]
    public void Constructor_WithControlCharacter_IsRejected()
    {
        var nameWithControlCharacter = "Em" + (char)1 + "ail";

        Assert.Throws<ArgumentException>(() => new LogicalName(nameWithControlCharacter));
    }

    [Fact]
    public void Constructor_TrimsSurroundingWhitespace()
    {
        Assert.Equal("Email", new LogicalName("  Email  ").Value);
    }

    [Fact]
    public void Equality_IsCaseSensitive()
    {
        Assert.NotEqual(new LogicalName("Email"), new LogicalName("email"));
    }
}

public sealed class EncryptedDataScopeTests
{
    [Fact]
    public void Constructor_WithValidNames_Succeeds()
    {
        var scope = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"));

        Assert.Equal("Customer.Email", scope.ToString());
    }

    [Fact]
    public void Constructor_WithNullEntity_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new EncryptedDataScope(null!, new LogicalName("Email")));
    }

    [Fact]
    public void Constructor_WithNullProperty_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new EncryptedDataScope(new LogicalName("Customer"), null!));
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        var a = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"));
        var b = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"));

        Assert.Equal(a, b);
    }

    [Fact]
    public void Equality_DistinguishesProperty()
    {
        var a = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email"));
        var b = new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Phone"));

        Assert.NotEqual(a, b);
    }
}

public sealed class EncryptionContextTests
{
    private static EncryptedDataScope Scope() =>
        new(new LogicalName("Customer"), new LogicalName("Email"));

    [Fact]
    public void Constructor_WithValidArguments_Succeeds()
    {
        var context = new EncryptionContext(new TenantId("acme"), Scope());

        Assert.Equal(new TenantId("acme"), context.Tenant);
    }

    [Fact]
    public void Constructor_WithNullTenant_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new EncryptionContext(null!, Scope()));
    }

    [Fact]
    public void Constructor_WithNullScope_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new EncryptionContext(new TenantId("acme"), null!));
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        var a = new EncryptionContext(new TenantId("acme"), Scope());
        var b = new EncryptionContext(new TenantId("acme"), Scope());

        Assert.Equal(a, b);
    }

    [Fact]
    public void Equality_DistinguishesTenant()
    {
        var a = new EncryptionContext(new TenantId("acme"), Scope());
        var b = new EncryptionContext(new TenantId("globex"), Scope());

        Assert.NotEqual(a, b);
    }
}

public sealed class AadSchemeIdTests
{
    [Fact]
    public void KnownSchemes_HaveExpectedRegistryBytes()
    {
        Assert.Equal(0x01, AadSchemeId.HeaderBound.Value);
        Assert.Equal(0x02, AadSchemeId.ContextBound.Value);
    }

    [Fact]
    public void Constructor_WithZero_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AadSchemeId(0));
    }

    [Fact]
    public void Default_IsUnspecifiedSentinel()
    {
        Assert.Equal(0, default(AadSchemeId).Value);
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        Assert.Equal(AadSchemeId.HeaderBound, new AadSchemeId(0x01));
        Assert.Equal("0x01", AadSchemeId.HeaderBound.ToString());
    }
}

public sealed class AadDescriptorTests
{
    [Fact]
    public void HeaderBound_HasExpectedSchemeAndBinding()
    {
        Assert.Equal(AadSchemeId.HeaderBound, AadDescriptor.HeaderBound.SchemeId);
        Assert.False(AadDescriptor.HeaderBound.BindsEntityId);
    }

    [Fact]
    public void HeaderBound_IsStableInstance()
    {
        Assert.Equal(AadDescriptor.HeaderBound, AadDescriptor.HeaderBound);
    }
}
