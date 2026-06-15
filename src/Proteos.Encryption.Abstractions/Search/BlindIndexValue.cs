namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The computed blind index of a value: the bytes stored in the shadow column and compared for
/// exact-match search. It is a deterministic, keyed digest — equal plaintexts yield equal values
/// — and therefore leaks equality and frequency by design.
/// </summary>
public sealed class BlindIndexValue : IEquatable<BlindIndexValue>
{
    private readonly byte[] _value;

    private BlindIndexValue(byte[] value) => _value = value;

    /// <summary>Creates a blind index value from its bytes. The input is copied.</summary>
    /// <exception cref="ArgumentException">The value is empty.</exception>
    public static BlindIndexValue Create(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("Blind index value must not be empty.", nameof(value));
        }

        return new BlindIndexValue(value.ToArray());
    }

    /// <summary>Length of the value in bytes.</summary>
    public int Length => _value.Length;

    /// <summary>Read-only view over the value bytes.</summary>
    public ReadOnlySpan<byte> Span => _value;

    /// <summary>Read-only memory view over the value bytes.</summary>
    public ReadOnlyMemory<byte> Memory => _value;

    /// <summary>Returns a defensive copy of the value bytes.</summary>
    public byte[] ToArray() => (byte[])_value.Clone();

    public bool Equals(BlindIndexValue? other) => other is not null && _value.AsSpan().SequenceEqual(other._value);

    public override bool Equals(object? obj) => Equals(obj as BlindIndexValue);

    public override int GetHashCode() => ByteSequence.GetHashCode(_value);

    public static bool operator ==(BlindIndexValue? left, BlindIndexValue? right) => left is null ? right is null : left.Equals(right);

    public static bool operator !=(BlindIndexValue? left, BlindIndexValue? right) => !(left == right);

    public override string ToString() => Convert.ToHexString(_value);
}
