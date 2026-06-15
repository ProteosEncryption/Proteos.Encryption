using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// Serializes a <see cref="CiphertextEnvelope"/> to its version 1 binary form, parses that form
/// back, and produces the Additional Authenticated Data for a header.
/// </summary>
/// <remarks>
/// This contract lives in Core, not Abstractions: the binary format (its layout, limits and
/// suite registry) is the stable contract that consumers depend on and already lives in
/// Abstractions; the codec is the behaviour that acts on it. Consumers interact with encryption
/// through the encryptor and blind-index contracts, not the codec, and the format is singular
/// and versioned, so there is no need to abstract over alternative codec implementations.
/// </remarks>
public interface ICiphertextEnvelopeCodec
{
    /// <summary>Serializes an envelope to its binary form.</summary>
    /// <exception cref="ArgumentNullException">The envelope is null.</exception>
    /// <exception cref="ArgumentException">The envelope cannot be represented in the version 1 format (unsupported version/suite/scheme, or nonce/tag length mismatch).</exception>
    byte[] Serialize(CiphertextEnvelope envelope);

    /// <summary>Parses a binary buffer into an envelope.</summary>
    /// <exception cref="EnvelopeParseException">The buffer is not a valid version 1 envelope.</exception>
    CiphertextEnvelope Parse(ReadOnlySpan<byte> data);

    /// <summary>Attempts to parse a binary buffer into an envelope without throwing.</summary>
    /// <returns><see langword="true"/> on success, with <paramref name="envelope"/> set and <paramref name="error"/> null; otherwise <see langword="false"/>.</returns>
    bool TryParse(ReadOnlySpan<byte> data, out CiphertextEnvelope? envelope, out EnvelopeParseError? error);

    /// <summary>
    /// Builds the Additional Authenticated Data for a header:
    /// <c>Version || CryptoSuiteId || AadSchemeId || KeyId</c>. The magic marker, all length
    /// prefixes and the nonce/tag/ciphertext are not part of the AAD.
    /// </summary>
    /// <exception cref="ArgumentNullException">The header is null.</exception>
    byte[] CreateAad(CiphertextEnvelopeHeader header);
}
