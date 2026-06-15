using Proteos.Encryption.Abstractions;
using Proteos.Encryption.AzureKeyVault;
using Xunit;

namespace Proteos.Encryption.AzureKeyVault.Tests;

public sealed class AzureKeyVaultKeyReferenceTests
{
    [Fact]
    public void Parse_VersionedIdentifier_ExposesAllParts()
    {
        var reference = AzureKeyVaultKeyReference.Parse("https://my-vault.vault.azure.net/keys/proteos-kek/abcdef0123456789");

        Assert.Equal("https://my-vault.vault.azure.net/keys/proteos-kek/abcdef0123456789", reference.KeyIdentifier.ToString());
        Assert.Equal("https://my-vault.vault.azure.net/", reference.VaultUri.ToString());
        Assert.Equal("proteos-kek", reference.KeyName);
        Assert.Equal("abcdef0123456789", reference.KeyVersion);
        Assert.True(reference.HasVersion);
    }

    [Fact]
    public void Parse_VersionlessIdentifier_HasNoVersion()
    {
        var reference = AzureKeyVaultKeyReference.Parse("https://my-vault.vault.azure.net/keys/proteos-kek");

        Assert.Equal("proteos-kek", reference.KeyName);
        Assert.Null(reference.KeyVersion);
        Assert.False(reference.HasVersion);
    }

    [Fact]
    public void FromProviderKeyReference_AzureKind_Parses()
    {
        var providerReference = new ProviderKeyReference(KeyProviderKind.AzureKeyVault, "https://v.vault.azure.net/keys/k/v1");

        var reference = AzureKeyVaultKeyReference.FromProviderKeyReference(providerReference);

        Assert.Equal("k", reference.KeyName);
        Assert.Equal("v1", reference.KeyVersion);
    }

    [Fact]
    public void FromProviderKeyReference_WrongProviderKind_Throws()
    {
        var providerReference = new ProviderKeyReference(KeyProviderKind.AwsKms, "arn:aws:kms:...");

        var exception = Assert.Throws<ArgumentException>(() => AzureKeyVaultKeyReference.FromProviderKeyReference(providerReference));
        Assert.Contains("AwsKms", exception.Message);
    }

    [Fact]
    public void FromProviderKeyReference_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AzureKeyVaultKeyReference.FromProviderKeyReference(null!));
    }

    [Theory]
    [InlineData("http://v.vault.azure.net/keys/k/v1")]   // not https
    [InlineData("https://v.vault.azure.net/secrets/k")]  // not a key path
    [InlineData("https://v.vault.azure.net/keys")]       // missing key name
    [InlineData("https://v.vault.azure.net/keys/k/v1/extra")] // too many segments
    [InlineData("not-a-uri")]                            // not absolute
    [InlineData("ftp://host/keys/k")]                    // wrong scheme
    public void Parse_InvalidIdentifier_Throws(string identifier)
    {
        Assert.Throws<ArgumentException>(() => AzureKeyVaultKeyReference.Parse(identifier));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_NullOrWhitespace_Throws(string? identifier)
    {
        Assert.ThrowsAny<ArgumentException>(() => AzureKeyVaultKeyReference.Parse(identifier!));
    }
}
