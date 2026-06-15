using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.Core.Tests.Keys;

/// <summary>
/// A non-cryptographic fake <see cref="IKeyProvider"/> for tests. It "wraps" by prefixing a KEK
/// marker and XOR-ing, and refuses to unwrap a blob whose marker does not match — which models a
/// wrong-KEK / unwrap failure. It is deliberately insecure and is never a production provider.
/// </summary>
internal sealed class InMemoryKeyProvider : IKeyProvider
{
    private readonly byte _kek;

    public InMemoryKeyProvider(byte kek) => _kek = kek;

    public string ProviderId => "in-memory-fake";

    public ValueTask<WrappedKey> WrapAsync(KeyId keyId, ReadOnlyMemory<byte> plaintextKey, CancellationToken cancellationToken = default)
    {
        var source = plaintextKey.Span;
        var cipher = new byte[source.Length + 1];
        cipher[0] = _kek;
        for (var i = 0; i < source.Length; i++)
        {
            cipher[i + 1] = (byte)(source[i] ^ _kek);
        }

        return new ValueTask<WrappedKey>(WrappedKey.Create(keyId, cipher));
    }

    public ValueTask<byte[]> UnwrapAsync(WrappedKey wrappedKey, CancellationToken cancellationToken = default)
    {
        var cipher = wrappedKey.Ciphertext.Span;
        if (cipher.Length == 0 || cipher[0] != _kek)
        {
            throw new KeyResolutionException("The wrapped key could not be unwrapped with this key-encryption key.");
        }

        var plain = new byte[cipher.Length - 1];
        for (var i = 0; i < plain.Length; i++)
        {
            plain[i] = (byte)(cipher[i + 1] ^ _kek);
        }

        return new ValueTask<byte[]>(plain);
    }
}
