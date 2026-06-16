using Proteos.Encryption.Abstractions;
using Proteos.Encryption.GoogleCloudKms;
using Xunit;

namespace Proteos.Encryption.GoogleCloudKms.Tests;

public sealed class GoogleCloudKmsKeyReferenceTests
{
    private const string ValidName = "projects/my-project/locations/europe-west3/keyRings/proteos/cryptoKeys/kek";

    [Fact]
    public void Parse_ValidName_ExposesAllParts()
    {
        var reference = GoogleCloudKmsKeyReference.Parse(ValidName);

        Assert.Equal(ValidName, reference.KeyName);
        Assert.Equal("my-project", reference.ProjectId);
        Assert.Equal("europe-west3", reference.LocationId);
        Assert.Equal("proteos", reference.KeyRingId);
        Assert.Equal("kek", reference.CryptoKeyId);
    }

    [Fact]
    public void Parse_TrimsWhitespace()
    {
        var reference = GoogleCloudKmsKeyReference.Parse($"  {ValidName}  ");

        Assert.Equal(ValidName, reference.KeyName);
    }

    [Fact]
    public void Parse_VersionQualifiedName_Throws()
    {
        var versioned = $"{ValidName}/cryptoKeyVersions/3";

        var exception = Assert.Throws<ArgumentException>(() => GoogleCloudKmsKeyReference.Parse(versioned));
        Assert.Contains("cryptoKeyVersions", exception.Message);
    }

    [Fact]
    public void Parse_CryptoKeyNamedCryptoKeyVersions_IsAccepted()
    {
        // 'cryptoKeyVersions' is a valid CryptoKey id. Only a trailing /cryptoKeyVersions/<version>
        // segment makes a name version-qualified, so the check must be positional, not a substring match.
        var name = "projects/my-project/locations/europe-west3/keyRings/proteos/cryptoKeys/cryptoKeyVersions";

        var reference = GoogleCloudKmsKeyReference.Parse(name);

        Assert.Equal("cryptoKeyVersions", reference.CryptoKeyId);
        Assert.Equal(name, reference.KeyName);
    }

    [Theory]
    [InlineData("projects/p/locations/l/keyRings/r/cryptoKeys")]            // missing key id
    [InlineData("projects/p/locations/l/keyRings/r/cryptoKeys/k/extra")]   // too many segments
    [InlineData("projects/p/locations/l/cryptoKeys/k")]                    // missing keyRings section
    [InlineData("project/p/locations/l/keyRings/r/cryptoKeys/k")]          // wrong literal 'project'
    [InlineData("projects//locations/l/keyRings/r/cryptoKeys/k")]          // empty project segment
    [InlineData("projects/p/locations/l/keyRings/r/cryptoKeys/k!")]        // invalid character
    [InlineData("arn:aws:kms:eu-central-1:123:key/abc")]                   // a different provider's form
    public void Parse_InvalidName_Throws(string name)
    {
        Assert.Throws<ArgumentException>(() => GoogleCloudKmsKeyReference.Parse(name));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_NullOrWhitespace_Throws(string? name)
    {
        Assert.ThrowsAny<ArgumentException>(() => GoogleCloudKmsKeyReference.Parse(name!));
    }

    [Fact]
    public void FromProviderKeyReference_GoogleKind_Parses()
    {
        var providerReference = new ProviderKeyReference(KeyProviderKind.GoogleKms, ValidName);

        var reference = GoogleCloudKmsKeyReference.FromProviderKeyReference(providerReference);

        Assert.Equal("kek", reference.CryptoKeyId);
    }

    [Fact]
    public void FromProviderKeyReference_WrongProviderKind_Throws()
    {
        var providerReference = new ProviderKeyReference(KeyProviderKind.AwsKms, "arn:aws:kms:...");

        var exception = Assert.Throws<ArgumentException>(() => GoogleCloudKmsKeyReference.FromProviderKeyReference(providerReference));
        Assert.Contains("AwsKms", exception.Message);
    }

    [Fact]
    public void FromProviderKeyReference_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => GoogleCloudKmsKeyReference.FromProviderKeyReference(null!));
    }

    [Fact]
    public void ToString_ReturnsCanonicalName()
    {
        Assert.Equal(ValidName, GoogleCloudKmsKeyReference.Parse(ValidName).ToString());
    }
}
