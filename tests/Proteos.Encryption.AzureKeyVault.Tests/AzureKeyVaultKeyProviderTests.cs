using Azure;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.AzureKeyVault;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.AzureKeyVault.Tests;

public sealed class AzureKeyVaultKeyProviderTests
{
    private static readonly KeyId SampleKeyId =
        KeyId.FromBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 1 });

    [Fact]
    public void ProviderId_IsStable()
    {
        var provider = new AzureKeyVaultKeyProvider(new FakeKeyVaultWrapClient());

        Assert.Equal("azure-key-vault", provider.ProviderId);
    }

    [Fact]
    public void WrapAlgorithm_IsRsaOaep256()
    {
        Assert.Equal("RSA-OAEP-256", AzureKeyVaultKeyProvider.WrapAlgorithm);
    }

    [Fact]
    public async Task Wrap_CallsClientWithRsaOaep256_AndReturnsWrappedKey()
    {
        var client = new FakeKeyVaultWrapClient();
        var provider = new AzureKeyVaultKeyProvider(client);

        var wrapped = await provider.WrapAsync(SampleKeyId, new byte[] { 10, 20, 30 });

        Assert.Equal("RSA-OAEP-256", client.LastWrapAlgorithm);
        Assert.Equal(SampleKeyId, wrapped.KeyId);
        Assert.Equal(new byte[] { 10, 20, 30 }, wrapped.Ciphertext.ToArray());
    }

    [Fact]
    public async Task Unwrap_CallsClientWithRsaOaep256_AndReturnsPlaintext()
    {
        var client = new FakeKeyVaultWrapClient();
        var provider = new AzureKeyVaultKeyProvider(client);
        var wrapped = WrappedKey.Create(SampleKeyId, new byte[] { 9, 8, 7 });

        var plaintext = await provider.UnwrapAsync(wrapped);

        Assert.Equal("RSA-OAEP-256", client.LastUnwrapAlgorithm);
        Assert.Equal(new byte[] { 9, 8, 7 }, plaintext);
    }

    [Fact]
    public async Task WrapThenUnwrap_RoundTrips()
    {
        // A toy reversible "KEK": wrap appends a byte, unwrap removes it. Proves the provider passes the
        // wrapped bytes back through unwrap unchanged.
        var client = new FakeKeyVaultWrapClient(
            wrap: p => [.. p.ToArray(), 0xFF],
            unwrap: c => c.ToArray()[..^1]);
        var provider = new AzureKeyVaultKeyProvider(client);
        var tmk = new byte[] { 42, 43, 44, 45 };

        var wrapped = await provider.WrapAsync(SampleKeyId, tmk);
        var unwrapped = await provider.UnwrapAsync(wrapped);

        Assert.NotEqual(tmk, wrapped.Ciphertext.ToArray());
        Assert.Equal(tmk, unwrapped);
    }

    [Fact]
    public async Task Wrap_NullKeyId_Throws()
    {
        var provider = new AzureKeyVaultKeyProvider(new FakeKeyVaultWrapClient());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.WrapAsync(null!, new byte[] { 1 }));
    }

    [Fact]
    public async Task Wrap_EmptyPlaintext_Throws()
    {
        var provider = new AzureKeyVaultKeyProvider(new FakeKeyVaultWrapClient());

        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.WrapAsync(SampleKeyId, ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public async Task Unwrap_NullWrappedKey_Throws()
    {
        var provider = new AzureKeyVaultKeyProvider(new FakeKeyVaultWrapClient());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.UnwrapAsync(null!));
    }

    [Fact]
    public async Task Wrap_ClientFailure_IsWrappedInProviderException()
    {
        var azureFailure = new RequestFailedException(503, "Key Vault unavailable");
        var provider = new AzureKeyVaultKeyProvider(new FakeKeyVaultWrapClient(throwOnCall: azureFailure));

        var exception = await Assert.ThrowsAsync<KeyVaultKeyProviderException>(
            async () => await provider.WrapAsync(SampleKeyId, new byte[] { 1, 2, 3 }));

        Assert.Same(azureFailure, exception.InnerException);
        Assert.DoesNotContain("1, 2, 3", exception.Message); // no key material leaks into the message
    }

    [Fact]
    public async Task Unwrap_ClientFailure_IsWrappedInProviderException()
    {
        var azureFailure = new RequestFailedException(403, "Forbidden");
        var provider = new AzureKeyVaultKeyProvider(new FakeKeyVaultWrapClient(throwOnCall: azureFailure));
        var wrapped = WrappedKey.Create(SampleKeyId, new byte[] { 5, 6, 7 });

        var exception = await Assert.ThrowsAsync<KeyVaultKeyProviderException>(
            async () => await provider.UnwrapAsync(wrapped));

        Assert.Same(azureFailure, exception.InnerException);
    }

    // --- DI extension (real production path: a real CryptographyClient is built, but offline) ---

    [Fact]
    public void AddProteosAzureKeyVault_RegistersProvider()
    {
        var services = new ServiceCollection()
            .AddProteosAzureKeyVault(o => o.KeyIdentifier = new Uri("https://v.vault.azure.net/keys/kek/v1"))
            .BuildServiceProvider();

        var provider = services.GetRequiredService<AzureKeyVaultKeyProvider>();

        Assert.Equal("azure-key-vault", provider.ProviderId);
    }

    [Fact]
    public void AddProteosAzureKeyVault_MissingKeyIdentifier_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddProteosAzureKeyVault(_ => { }));
    }

    [Fact]
    public void AddProteosAzureKeyVault_InvalidKeyIdentifier_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new ServiceCollection().AddProteosAzureKeyVault(o => o.KeyIdentifier = new Uri("https://v.vault.azure.net/secrets/not-a-key")));
    }

    // --- Architecture guard: Core and EF must not depend on Azure ---

    [Theory]
    [InlineData(typeof(AesGcmValueEncryptionService))]       // Proteos.Encryption.Core
    [InlineData(typeof(EncryptedAttribute))]                 // Proteos.Encryption.EntityFrameworkCore
    public void CoreAndEf_DoNotReferenceAzure(Type typeFromAssembly)
    {
        var referenced = typeFromAssembly.Assembly.GetReferencedAssemblies();

        Assert.DoesNotContain(referenced, name => name.Name!.StartsWith("Azure", StringComparison.OrdinalIgnoreCase));
    }
}
