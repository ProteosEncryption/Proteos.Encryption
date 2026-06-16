using Proteos.Encryption.GoogleCloudKms;

namespace Proteos.Encryption.GoogleCloudKms.Tests;

/// <summary>
/// A test double for <see cref="IGoogleKmsCryptoClient"/>. It records the key name it was called with,
/// optionally transforms the bytes, and can be configured to throw — so the provider can be tested
/// without any Google Cloud call. Default behaviour is identity (encrypt and decrypt return the input).
/// </summary>
internal sealed class FakeGoogleKmsCryptoClient : IGoogleKmsCryptoClient
{
    private readonly Func<ReadOnlyMemory<byte>, byte[]>? _encrypt;
    private readonly Func<ReadOnlyMemory<byte>, byte[]>? _decrypt;
    private readonly Exception? _throw;

    public FakeGoogleKmsCryptoClient(
        Func<ReadOnlyMemory<byte>, byte[]>? encrypt = null,
        Func<ReadOnlyMemory<byte>, byte[]>? decrypt = null,
        Exception? throwOnCall = null)
    {
        _encrypt = encrypt;
        _decrypt = decrypt;
        _throw = throwOnCall;
    }

    public string? LastEncryptKeyName { get; private set; }

    public string? LastDecryptKeyName { get; private set; }

    public ValueTask<byte[]> EncryptAsync(string keyName, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken)
    {
        LastEncryptKeyName = keyName;
        if (_throw is not null)
        {
            throw _throw;
        }

        return ValueTask.FromResult(_encrypt?.Invoke(plaintextKey) ?? plaintextKey.ToArray());
    }

    public ValueTask<byte[]> DecryptAsync(string keyName, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken)
    {
        LastDecryptKeyName = keyName;
        if (_throw is not null)
        {
            throw _throw;
        }

        return ValueTask.FromResult(_decrypt?.Invoke(wrappedKey) ?? wrappedKey.ToArray());
    }
}
