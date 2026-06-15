namespace Proteos.Encryption.Abstractions;

/// <summary>
/// A Tenant Master Key in wrapped form: the key-encryption-key (KEK) ciphertext together with
/// the <see cref="KeyId"/> it belongs to. A wrapped key is safe to store and back up — it is
/// useless without KEK access — which is why it can be modelled as an ordinary value object.
/// </summary>
public sealed class WrappedKey : IEquatable<WrappedKey>
{
    private readonly byte[] _ciphertext;

    private WrappedKey(KeyId keyId, byte[] ciphertext)
    {
        KeyId = keyId;
        _ciphertext = ciphertext;
    }

    /// <summary>Creates a wrapped key from its key id and KEK ciphertext. The ciphertext is copied.</summary>
    /// <exception cref="ArgumentNullException">Key id is null.</exception>
    /// <exception cref="ArgumentException">Ciphertext is empty.</exception>
    public static WrappedKey Create(KeyId keyId, ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(keyId);

        if (ciphertext.IsEmpty)
        {
            throw new ArgumentException("Wrapped key ciphertext must not be empty.", nameof(ciphertext));
        }

        return new WrappedKey(keyId, ciphertext.ToArray());
    }

    /// <summary>The identifier of the master key this ciphertext wraps.</summary>
    public KeyId KeyId { get; }

    /// <summary>Read-only view over the KEK ciphertext.</summary>
    public ReadOnlyMemory<byte> Ciphertext => _ciphertext;

    /// <summary>Returns a defensive copy of the KEK ciphertext.</summary>
    public byte[] ToArray() => (byte[])_ciphertext.Clone();

    public bool Equals(WrappedKey? other) =>
        other is not null && KeyId.Equals(other.KeyId) && _ciphertext.AsSpan().SequenceEqual(other._ciphertext);

    public override bool Equals(object? obj) => Equals(obj as WrappedKey);

    public override int GetHashCode() => HashCode.Combine(KeyId, ByteSequence.GetHashCode(_ciphertext));

    public static bool operator ==(WrappedKey? left, WrappedKey? right) => left is null ? right is null : left.Equals(right);

    public static bool operator !=(WrappedKey? left, WrappedKey? right) => !(left == right);
}
