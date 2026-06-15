namespace Proteos.Encryption.Core;

/// <summary>
/// Supplies nonce bytes for authenticated encryption. The production implementation draws from a
/// cryptographically secure RNG; the seam is internal so tests can inject a fixed nonce for
/// golden vectors without exposing a non-random nonce path on the public API.
/// </summary>
internal interface INonceSource
{
    void Fill(Span<byte> destination);
}
