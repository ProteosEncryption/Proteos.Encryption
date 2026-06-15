using Proteos.Encryption.Abstractions;
using Proteos.Encryption.AwsKms;
using Xunit;

namespace Proteos.Encryption.AwsKms.Tests;

public sealed class AwsKmsKeyReferenceTests
{
    [Fact]
    public void Parse_KeyArn_ExposesRegion()
    {
        var reference = AwsKmsKeyReference.Parse("arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab");

        Assert.Equal(AwsKmsKeyReferenceKind.KeyArn, reference.Kind);
        Assert.Equal("eu-central-1", reference.Region);
        Assert.StartsWith("arn:aws:kms:", reference.KeyId);
    }

    [Fact]
    public void Parse_AliasArn_IsAliasArn_WithRegion()
    {
        var reference = AwsKmsKeyReference.Parse("arn:aws:kms:us-east-1:123456789012:alias/proteos-key");

        Assert.Equal(AwsKmsKeyReferenceKind.AliasArn, reference.Kind);
        Assert.Equal("us-east-1", reference.Region);
    }

    [Fact]
    public void Parse_BareKeyId_HasNoRegion()
    {
        var reference = AwsKmsKeyReference.Parse("1234abcd-12ab-34cd-56ef-1234567890ab");

        Assert.Equal(AwsKmsKeyReferenceKind.KeyId, reference.Kind);
        Assert.Null(reference.Region);
    }

    [Fact]
    public void Parse_AliasName_HasNoRegion()
    {
        var reference = AwsKmsKeyReference.Parse("alias/proteos-key");

        Assert.Equal(AwsKmsKeyReferenceKind.AliasName, reference.Kind);
        Assert.Null(reference.Region);
    }

    [Fact]
    public void FromProviderKeyReference_AwsKind_Parses()
    {
        var providerReference = new ProviderKeyReference(KeyProviderKind.AwsKms, "arn:aws:kms:eu-west-1:123456789012:key/abcd");

        var reference = AwsKmsKeyReference.FromProviderKeyReference(providerReference);

        Assert.Equal("eu-west-1", reference.Region);
    }

    [Fact]
    public void FromProviderKeyReference_WrongProviderKind_Throws()
    {
        var providerReference = new ProviderKeyReference(KeyProviderKind.AzureKeyVault, "https://v.vault.azure.net/keys/k/v1");

        var exception = Assert.Throws<ArgumentException>(() => AwsKmsKeyReference.FromProviderKeyReference(providerReference));
        Assert.Contains("AzureKeyVault", exception.Message);
    }

    [Fact]
    public void FromProviderKeyReference_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AwsKmsKeyReference.FromProviderKeyReference(null!));
    }

    [Theory]
    [InlineData("arn:aws:s3:::bucket/key")]                 // not kms
    [InlineData("arn:aws:kms:::key/abcd")]                  // empty region
    [InlineData("arn:aws:kms:eu-central-1:123:secret/x")]   // not key/alias
    [InlineData("arn:aws:kms:eu-central-1:123:key/")]       // empty key name
    [InlineData("alias/")]                                  // empty alias name
    [InlineData("has space")]                               // bare id with whitespace
    [InlineData("foo:bar")]                                 // bare id with colon
    public void Parse_Invalid_Throws(string reference)
    {
        Assert.Throws<ArgumentException>(() => AwsKmsKeyReference.Parse(reference));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_NullOrWhitespace_Throws(string? reference)
    {
        Assert.ThrowsAny<ArgumentException>(() => AwsKmsKeyReference.Parse(reference!));
    }
}
