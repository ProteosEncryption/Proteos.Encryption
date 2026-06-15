namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Internal helpers for byte-backed value objects: content-based hashing shared by the
/// immutable identifiers and envelope fields. Equality itself is expressed inline via
/// <see cref="System.MemoryExtensions.SequenceEqual{T}(System.ReadOnlySpan{T}, System.ReadOnlySpan{T})"/>
/// at each call site, which keeps the comparison semantics visible where they matter.
/// </summary>
internal static class ByteSequence
{
    public static int GetHashCode(ReadOnlySpan<byte> value)
    {
        var hash = new HashCode();
        hash.AddBytes(value);
        return hash.ToHashCode();
    }
}
