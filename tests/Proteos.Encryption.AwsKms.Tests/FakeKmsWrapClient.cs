using Proteos.Encryption.AwsKms;

namespace Proteos.Encryption.AwsKms.Tests;

/// <summary>
/// A test double for <see cref="IKmsWrapClient"/>. It records the key id it was called with, optionally
/// transforms the bytes, and can be configured to throw — so the provider can be tested without any AWS
/// call. Default behaviour is identity (encrypt and decrypt return the input).
/// </summary>
internal sealed class FakeKmsWrapClient : IKmsWrapClient
{
    private readonly Func<ReadOnlyMemory<byte>, byte[]>? _encrypt;
    private readonly Func<ReadOnlyMemory<byte>, byte[]>? _decrypt;
    private readonly Exception? _throw;

    public FakeKmsWrapClient(
        Func<ReadOnlyMemory<byte>, byte[]>? encrypt = null,
        Func<ReadOnlyMemory<byte>, byte[]>? decrypt = null,
        Exception? throwOnCall = null)
    {
        _encrypt = encrypt;
        _decrypt = decrypt;
        _throw = throwOnCall;
    }

    public string? LastEncryptKeyId { get; private set; }

    public string? LastDecryptKeyId { get; private set; }

    public ValueTask<byte[]> EncryptAsync(string keyId, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken)
    {
        LastEncryptKeyId = keyId;
        if (_throw is not null)
        {
            throw _throw;
        }

        return ValueTask.FromResult(_encrypt?.Invoke(plaintextKey) ?? plaintextKey.ToArray());
    }

    public ValueTask<byte[]> DecryptAsync(string keyId, ReadOnlyMemory<byte> wrappedKey, CancellationToken cancellationToken)
    {
        LastDecryptKeyId = keyId;
        if (_throw is not null)
        {
            throw _throw;
        }

        return ValueTask.FromResult(_decrypt?.Invoke(wrappedKey) ?? wrappedKey.ToArray());
    }
}
