namespace Proteos.Encryption.Core.Tests.Vectors;

/// <summary>Hex helpers for readable test vectors. Empty string maps to an empty array.</summary>
internal static class Hex
{
    public static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    public static string ToHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
