using Proteos.Encryption.AzureKeyVault;

namespace Proteos.Encryption.AzureKeyVault.Tests;

/// <summary>
/// A test double for <see cref="IKeyVaultWrapClient"/>. It records the algorithm it was called with,
/// optionally transforms the bytes, and can be configured to throw — so the provider can be tested
/// without any Azure call. Default behaviour is identity (wrap and unwrap return the input), which is
/// enough to verify the provider's plumbing and round-trip.
/// </summary>
internal sealed class FakeKeyVaultWrapClient : IKeyVaultWrapClient
{
    private readonly Func<ReadOnlyMemory<byte>, byte[]>? _wrap;
    private readonly Func<ReadOnlyMemory<byte>, byte[]>? _unwrap;
    private readonly Exception? _throw;

    public FakeKeyVaultWrapClient(
        Func<ReadOnlyMemory<byte>, byte[]>? wrap = null,
        Func<ReadOnlyMemory<byte>, byte[]>? unwrap = null,
        Exception? throwOnCall = null)
    {
        _wrap = wrap;
        _unwrap = unwrap;
        _throw = throwOnCall;
    }

    public string KeyIdentifier => "https://fake-vault.vault.azure.net/keys/fake-kek/v1";

    public string? LastWrapAlgorithm { get; private set; }

    public string? LastUnwrapAlgorithm { get; private set; }

    public ValueTask<byte[]> WrapKeyAsync(string algorithm, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken)
    {
        LastWrapAlgorithm = algorithm;
        if (_throw is not null)
        {
            throw _throw;
        }

        return ValueTask.FromResult(_wrap?.Invoke(plaintextKey) ?? plaintextKey.ToArray());
    }

    public ValueTask<byte[]> UnwrapKeyAsync(string algorithm, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken)
    {
        LastUnwrapAlgorithm = algorithm;
        if (_throw is not null)
        {
            throw _throw;
        }

        return ValueTask.FromResult(_unwrap?.Invoke(wrappedKey) ?? wrappedKey.ToArray());
    }
}
