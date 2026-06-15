using System.Security.Cryptography;

namespace Proteos.Encryption.Core;

/// <summary>
/// Thin wrapper over the platform HKDF (RFC 5869) with SHA-256, the key-derivation function used
/// throughout the crypto core. It is a KDF, not a cipher: it derives subkeys for domain
/// separation but performs no encryption.
/// </summary>
internal static class Hkdf
{
    public static byte[] DeriveKey(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> info, int length)
    {
        var output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, output, salt: ReadOnlySpan<byte>.Empty, info: info);
        return output;
    }
}
