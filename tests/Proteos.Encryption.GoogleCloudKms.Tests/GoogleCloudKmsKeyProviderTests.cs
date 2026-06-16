using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.GoogleCloudKms;
using Xunit;

namespace Proteos.Encryption.GoogleCloudKms.Tests;

public sealed class GoogleCloudKmsKeyProviderTests
{
    private const string KeyName = "projects/my-project/locations/europe-west3/keyRings/proteos/cryptoKeys/kek";
    private static readonly GoogleCloudKmsKeyReference Reference = GoogleCloudKmsKeyReference.Parse(KeyName);

    private static readonly KeyId SampleKeyId =
        KeyId.FromBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 1 });

    [Fact]
    public void ProviderId_IsStable()
    {
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient());

        Assert.Equal("google-cloud-kms", provider.ProviderId);
    }

    [Fact]
    public async Task Wrap_CallsEncryptWithConfiguredKeyName_AndReturnsWrappedKey()
    {
        var client = new FakeGoogleKmsCryptoClient();
        var provider = new GoogleCloudKmsKeyProvider(Reference, client);

        var wrapped = await provider.WrapAsync(SampleKeyId, new byte[] { 10, 20, 30 });

        Assert.Equal(KeyName, client.LastEncryptKeyName);
        Assert.Equal(SampleKeyId, wrapped.KeyId);
        Assert.Equal(new byte[] { 10, 20, 30 }, wrapped.Ciphertext.ToArray());
    }

    [Fact]
    public async Task Unwrap_CallsDecryptWithConfiguredKeyName_AndReturnsPlaintext()
    {
        var client = new FakeGoogleKmsCryptoClient();
        var provider = new GoogleCloudKmsKeyProvider(Reference, client);
        var wrapped = WrappedKey.Create(SampleKeyId, new byte[] { 9, 8, 7 });

        var plaintext = await provider.UnwrapAsync(wrapped);

        Assert.Equal(KeyName, client.LastDecryptKeyName);
        Assert.Equal(new byte[] { 9, 8, 7 }, plaintext);
    }

    [Fact]
    public async Task WrapThenUnwrap_RoundTrips()
    {
        // A toy reversible "KEK": encrypt appends a byte, decrypt removes it. Proves the provider passes
        // the wrapped bytes back through decrypt unchanged.
        var client = new FakeGoogleKmsCryptoClient(
            encrypt: p => [.. p.ToArray(), 0xFF],
            decrypt: c => c.ToArray()[..^1]);
        var provider = new GoogleCloudKmsKeyProvider(Reference, client);
        var tmk = new byte[] { 42, 43, 44, 45 };

        var wrapped = await provider.WrapAsync(SampleKeyId, tmk);
        var unwrapped = await provider.UnwrapAsync(wrapped);

        Assert.NotEqual(tmk, wrapped.Ciphertext.ToArray());
        Assert.Equal(tmk, unwrapped);
    }

    [Fact]
    public async Task Wrap_NullKeyId_Throws()
    {
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.WrapAsync(null!, new byte[] { 1 }));
    }

    [Fact]
    public async Task Wrap_EmptyPlaintext_Throws()
    {
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient());

        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.WrapAsync(SampleKeyId, ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public async Task Unwrap_NullWrappedKey_Throws()
    {
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.UnwrapAsync(null!));
    }

    [Fact]
    public async Task Wrap_RpcFailure_IsWrappedInProviderException()
    {
        var rpcFailure = new RpcException(new Status(StatusCode.Unavailable, "KMS unavailable"));
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient(throwOnCall: rpcFailure));

        var exception = await Assert.ThrowsAsync<GoogleCloudKmsKeyProviderException>(
            async () => await provider.WrapAsync(SampleKeyId, new byte[] { 1, 2, 3 }));

        Assert.Same(rpcFailure, exception.InnerException);
        Assert.DoesNotContain("1, 2, 3", exception.Message); // no key material leaks into the message
    }

    [Fact]
    public async Task Unwrap_RpcFailure_IsWrappedInProviderException()
    {
        var rpcFailure = new RpcException(new Status(StatusCode.PermissionDenied, "Access denied"));
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient(throwOnCall: rpcFailure));
        var wrapped = WrappedKey.Create(SampleKeyId, new byte[] { 5, 6, 7 });

        var exception = await Assert.ThrowsAsync<GoogleCloudKmsKeyProviderException>(async () => await provider.UnwrapAsync(wrapped));

        Assert.Same(rpcFailure, exception.InnerException);
    }

    [Fact]
    public async Task Wrap_IntegrityFailure_SurfacesAsProviderException()
    {
        // The production crypto client throws GoogleCloudKmsKeyProviderException on a CRC32C mismatch; that
        // is already a Proteos exception and must propagate unchanged (not be re-wrapped).
        var integrityFailure = new GoogleCloudKmsKeyProviderException("integrity check failed");
        var provider = new GoogleCloudKmsKeyProvider(Reference, new FakeGoogleKmsCryptoClient(throwOnCall: integrityFailure));

        var exception = await Assert.ThrowsAsync<GoogleCloudKmsKeyProviderException>(
            async () => await provider.WrapAsync(SampleKeyId, new byte[] { 1, 2, 3 }));

        Assert.Same(integrityFailure, exception);
    }

    // --- DI extension: validation is eager; the KMS client is built lazily (not resolved here) ---

    [Fact]
    public void AddProteosGoogleCloudKms_RegistersProvider()
    {
        var services = new ServiceCollection().AddProteosGoogleCloudKms(o => o.KeyName = KeyName);

        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(GoogleCloudKmsKeyProvider));
    }

    [Fact]
    public void AddProteosGoogleCloudKms_MissingKeyName_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddProteosGoogleCloudKms(_ => { }));
    }

    [Fact]
    public void AddProteosGoogleCloudKms_InvalidKeyName_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddProteosGoogleCloudKms(o => o.KeyName = "projects/p/cryptoKeys/k"));
    }

    [Fact]
    public void AddProteosGoogleCloudKms_BothCredentialOptions_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddProteosGoogleCloudKms(o =>
        {
            o.KeyName = KeyName;
            o.CredentialsPath = "/path/to/key.json";
            o.JsonCredentials = "{}";
        }));
    }

    // --- Architecture guard: the provider depends only on Abstractions, not Core/EF/Azure/AWS ---

    [Fact]
    public void GoogleProvider_DependsOnlyOnAbstractions_NotOnOtherProviders()
    {
        var referenced = typeof(GoogleCloudKmsKeyProvider).Assembly.GetReferencedAssemblies();

        Assert.DoesNotContain(referenced, name => name.Name!.StartsWith("AWSSDK", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referenced, name => name.Name!.StartsWith("Azure", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referenced, name => name.Name! == "Proteos.Encryption.Core");
        Assert.DoesNotContain(referenced, name => name.Name! == "Proteos.Encryption.EntityFrameworkCore");
    }
}
