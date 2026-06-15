namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Opaque, vendor-neutral key identifier persisted inside the ciphertext envelope. It maps —
/// through the key catalogue — onto a concrete key reference; it is deliberately <b>not</b> a
/// raw KMS URI, so stored data never carries vendor lock-in.
/// </summary>
/// <remarks>
/// The identifier is treated as an opaque, length-bounded byte sequence so that future key
/// schemes (and provider migrations) remain representable without a format break. The
/// concrete Foundation-Release scheme (<c>TmkId(16) ‖ TmkVersion(2)</c>) is realised by the
/// envelope codec, keeping this abstraction scheme-agnostic. The envelope stores the length in
/// a single byte, hence the 1..255 bound.
/// </remarks>
public sealed class KeyId : IEquatable<KeyId>
{
    /// <summary>Minimum length, in bytes, of a key identifier.</summary>
    public const int MinLength = 1;

    /// <summary>Maximum length, in bytes, of a key identifier (single-byte length prefix in the envelope).</summary>
    public const int MaxLength = 255;

    private readonly byte[] _value;

    private KeyId(byte[] value) => _value = value;

    /// <summary>Creates a key identifier from an opaque byte sequence. The input is copied.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Length is outside <see cref="MinLength"/>..<see cref="MaxLength"/>.</exception>
    public static KeyId FromBytes(ReadOnlySpan<byte> value)
    {
        if (value.Length is < MinLength or > MaxLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                value.Length,
                $"Key id length must be between {MinLength} and {MaxLength} bytes.");
        }

        return new KeyId(value.ToArray());
    }

    /// <summary>Length of the identifier in bytes.</summary>
    public int Length => _value.Length;

    /// <summary>Read-only view over the identifier bytes.</summary>
    public ReadOnlySpan<byte> Span => _value;

    /// <summary>Read-only memory view over the identifier bytes.</summary>
    public ReadOnlyMemory<byte> Memory => _value;

    /// <summary>Returns a defensive copy of the identifier bytes.</summary>
    public byte[] ToArray() => (byte[])_value.Clone();

    public bool Equals(KeyId? other) => other is not null && _value.AsSpan().SequenceEqual(other._value);

    public override bool Equals(object? obj) => Equals(obj as KeyId);

    public override int GetHashCode() => ByteSequence.GetHashCode(_value);

    public static bool operator ==(KeyId? left, KeyId? right) => left is null ? right is null : left.Equals(right);

    public static bool operator !=(KeyId? left, KeyId? right) => !(left == right);

    public override string ToString() => Convert.ToHexString(_value);
}
