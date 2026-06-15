using System.Security.Cryptography;

namespace Proteos.Encryption.Core;

/// <summary>
/// The production nonce source: fresh bytes from a cryptographically secure RNG on every call.
/// Stateless and thread-safe.
/// </summary>
internal sealed class RandomNonceSource : INonceSource
{
    public static readonly RandomNonceSource Instance = new();

    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);
}
