using Proteos.Encryption.Core;

namespace Proteos.Encryption.Core.Tests.TestSupport;

/// <summary>
/// Test-only nonce source returning a fixed nonce, so end-to-end golden vectors are
/// reproducible. Lives in the test assembly and reaches the internal <see cref="INonceSource"/>
/// seam via InternalsVisibleTo; it is never part of the product.
/// </summary>
internal sealed class FixedNonceSource : INonceSource
{
    private readonly byte[] _nonce;

    public FixedNonceSource(byte[] nonce) => _nonce = nonce;

    public void Fill(Span<byte> destination) => _nonce.CopyTo(destination);
}
