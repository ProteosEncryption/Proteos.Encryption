using Amazon.KeyManagementService;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.AwsKms;
using Proteos.Encryption.AzureKeyVault;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.AwsKms.Tests;

public sealed class AwsKmsKeyProviderTests
{
    private const string KeyArn = "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    private static readonly AwsKmsKeyReference Reference = AwsKmsKeyReference.Parse(KeyArn);

    private static readonly KeyId SampleKeyId =
        KeyId.FromBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 1 });

    [Fact]
    public void ProviderId_IsStable()
    {
        var provider = new AwsKmsKeyProvider(Reference, new FakeKmsWrapClient());

        Assert.Equal("aws-kms", provider.ProviderId);
    }

    [Fact]
    public async Task Wrap_CallsEncryptWithConfiguredKeyId_AndReturnsWrappedKey()
    {
        var client = new FakeKmsWrapClient();
        var provider = new AwsKmsKeyProvider(Reference, client);

        var wrapped = await provider.WrapAsync(SampleKeyId, new byte[] { 10, 20, 30 });

        Assert.Equal(KeyArn, client.LastEncryptKeyId);
        Assert.Equal(SampleKeyId, wrapped.KeyId);
        Assert.Equal(new byte[] { 10, 20, 30 }, wrapped.Ciphertext.ToArray());
    }

    [Fact]
    public async Task Unwrap_CallsDecryptWithConfiguredKeyId_AndReturnsPlaintext()
    {
        var client = new FakeKmsWrapClient();
        var provider = new AwsKmsKeyProvider(Reference, client);
        var wrapped = WrappedKey.Create(SampleKeyId, new byte[] { 9, 8, 7 });

        var plaintext = await provider.UnwrapAsync(wrapped);

        Assert.Equal(KeyArn, client.LastDecryptKeyId);
        Assert.Equal(new byte[] { 9, 8, 7 }, plaintext);
    }

    [Fact]
    public async Task WrapThenUnwrap_RoundTrips()
    {
        // A toy reversible "KEK": encrypt appends a byte, decrypt removes it. Proves the provider passes
        // the wrapped bytes back through decrypt unchanged.
        var client = new FakeKmsWrapClient(
            encrypt: p => [.. p.ToArray(), 0xFF],
            decrypt: c => c.ToArray()[..^1]);
        var provider = new AwsKmsKeyProvider(Reference, client);
        var tmk = new byte[] { 42, 43, 44, 45 };

        var wrapped = await provider.WrapAsync(SampleKeyId, tmk);
        var unwrapped = await provider.UnwrapAsync(wrapped);

        Assert.NotEqual(tmk, wrapped.Ciphertext.ToArray());
        Assert.Equal(tmk, unwrapped);
    }

    [Fact]
    public async Task Wrap_NullKeyId_Throws()
    {
        var provider = new AwsKmsKeyProvider(Reference, new FakeKmsWrapClient());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.WrapAsync(null!, new byte[] { 1 }));
    }

    [Fact]
    public async Task Wrap_EmptyPlaintext_Throws()
    {
        var provider = new AwsKmsKeyProvider(Reference, new FakeKmsWrapClient());

        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.WrapAsync(SampleKeyId, ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public async Task Unwrap_NullWrappedKey_Throws()
    {
        var provider = new AwsKmsKeyProvider(Reference, new FakeKmsWrapClient());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.UnwrapAsync(null!));
    }

    [Fact]
    public async Task Wrap_ClientFailure_IsWrappedInProviderException()
    {
        var awsFailure = new AmazonKeyManagementServiceException("KMS unavailable");
        var provider = new AwsKmsKeyProvider(Reference, new FakeKmsWrapClient(throwOnCall: awsFailure));

        var exception = await Assert.ThrowsAsync<KmsKeyProviderException>(
            async () => await provider.WrapAsync(SampleKeyId, new byte[] { 1, 2, 3 }));

        Assert.Same(awsFailure, exception.InnerException);
        Assert.DoesNotContain("1, 2, 3", exception.Message); // no key material leaks into the message
    }

    [Fact]
    public async Task Unwrap_ClientFailure_IsWrappedInProviderException()
    {
        var awsFailure = new AmazonKeyManagementServiceException("Access denied");
        var provider = new AwsKmsKeyProvider(Reference, new FakeKmsWrapClient(throwOnCall: awsFailure));
        var wrapped = WrappedKey.Create(SampleKeyId, new byte[] { 5, 6, 7 });

        var exception = await Assert.ThrowsAsync<KmsKeyProviderException>(async () => await provider.UnwrapAsync(wrapped));

        Assert.Same(awsFailure, exception.InnerException);
    }

    // --- DI extension: validation is eager; the AWS client is built lazily (not resolved here) ---

    [Fact]
    public void AddProteosAwsKms_RegistersProvider()
    {
        var services = new ServiceCollection().AddProteosAwsKms(o => o.KeyId = KeyArn);

        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(AwsKmsKeyProvider));
    }

    [Fact]
    public void AddProteosAwsKms_MissingKeyId_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddProteosAwsKms(_ => { }));
    }

    [Fact]
    public void AddProteosAwsKms_InvalidKeyId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddProteosAwsKms(o => o.KeyId = "arn:aws:s3:::nope"));
    }

    // --- Architecture guard: Core, EF and the Azure package must not depend on AWS ---

    [Theory]
    [InlineData(typeof(AesGcmValueEncryptionService))]       // Proteos.Encryption.Core
    [InlineData(typeof(EncryptingSaveChangesInterceptor))]   // Proteos.Encryption.EntityFrameworkCore
    [InlineData(typeof(AzureKeyVaultKeyProvider))]           // Proteos.Encryption.AzureKeyVault
    public void CoreEfAndAzure_DoNotReferenceAws(Type typeFromAssembly)
    {
        var referenced = typeFromAssembly.Assembly.GetReferencedAssemblies();

        Assert.DoesNotContain(referenced, name => name.Name!.StartsWith("AWSSDK", StringComparison.OrdinalIgnoreCase));
    }
}
