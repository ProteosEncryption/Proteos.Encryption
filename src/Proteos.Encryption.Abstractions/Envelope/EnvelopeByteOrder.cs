namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Byte order used when a multi-byte integer is written into the ciphertext envelope. The
/// envelope fixes this so length fields are deterministic across platforms.
/// </summary>
public enum EnvelopeByteOrder
{
    /// <summary>Most significant byte first.</summary>
    BigEndian = 1,

    /// <summary>Least significant byte first.</summary>
    LittleEndian = 2,
}
