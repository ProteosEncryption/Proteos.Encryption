namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The logical representation of a ciphertext envelope: the authenticated <see cref="Header"/>
/// plus the AEAD nonce, authentication tag and ciphertext. This type models the format; the
/// binary serialization and parsing — including suite-specific length checks — are the codec's
/// responsibility.
/// </summary>
/// <remarks>
/// Validation here is structural and suite-agnostic: nonce and tag must be present, ciphertext
/// may be empty (an empty plaintext still produces a tag). Exact lengths (for the Foundation
/// Release: 12-byte nonce, 16-byte tag) are tied to the suite and enforced by the codec.
/// </remarks>
public sealed class CiphertextEnvelope : IEquatable<CiphertextEnvelope>
{
    private readonly byte[] _nonce;
    private readonly byte[] _tag;
    private readonly byte[] _ciphertext;

    private CiphertextEnvelope(CiphertextEnvelopeHeader header, byte[] nonce, byte[] tag, byte[] ciphertext)
    {
        Header = header;
        _nonce = nonce;
        _tag = tag;
        _ciphertext = ciphertext;
    }

    /// <summary>Creates an envelope. Nonce, tag and ciphertext are copied.</summary>
    /// <exception cref="ArgumentNullException">Header is null.</exception>
    /// <exception cref="ArgumentException">Nonce or tag is empty.</exception>
    public static CiphertextEnvelope Create(
        CiphertextEnvelopeHeader header,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(header);

        if (nonce.IsEmpty)
        {
            throw new ArgumentException("Nonce must not be empty.", nameof(nonce));
        }

        if (tag.IsEmpty)
        {
            throw new ArgumentException("Authentication tag must not be empty.", nameof(tag));
        }

        return new CiphertextEnvelope(header, nonce.ToArray(), tag.ToArray(), ciphertext.ToArray());
    }

    /// <summary>The authenticated envelope header.</summary>
    public CiphertextEnvelopeHeader Header { get; }

    /// <summary>Read-only view over the AEAD nonce.</summary>
    public ReadOnlyMemory<byte> Nonce => _nonce;

    /// <summary>Read-only view over the AEAD authentication tag.</summary>
    public ReadOnlyMemory<byte> Tag => _tag;

    /// <summary>Read-only view over the ciphertext (may be empty).</summary>
    public ReadOnlyMemory<byte> Ciphertext => _ciphertext;

    /// <summary>Returns a defensive copy of the nonce.</summary>
    public byte[] NonceToArray() => (byte[])_nonce.Clone();

    /// <summary>Returns a defensive copy of the authentication tag.</summary>
    public byte[] TagToArray() => (byte[])_tag.Clone();

    /// <summary>Returns a defensive copy of the ciphertext.</summary>
    public byte[] CiphertextToArray() => (byte[])_ciphertext.Clone();

    public bool Equals(CiphertextEnvelope? other) =>
        other is not null
        && Header.Equals(other.Header)
        && _nonce.AsSpan().SequenceEqual(other._nonce)
        && _tag.AsSpan().SequenceEqual(other._tag)
        && _ciphertext.AsSpan().SequenceEqual(other._ciphertext);

    public override bool Equals(object? obj) => Equals(obj as CiphertextEnvelope);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Header);
        hash.AddBytes(_nonce);
        hash.AddBytes(_tag);
        hash.AddBytes(_ciphertext);
        return hash.ToHashCode();
    }

    public static bool operator ==(CiphertextEnvelope? left, CiphertextEnvelope? right) =>
        left is null ? right is null : left.Equals(right);

    public static bool operator !=(CiphertextEnvelope? left, CiphertextEnvelope? right) => !(left == right);
}
