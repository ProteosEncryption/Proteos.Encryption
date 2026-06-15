using System.Buffers.Binary;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// The version 1 ciphertext envelope codec. Stateless and thread-safe. Serialization rejects any
/// envelope that cannot be represented in the format; parsing is strict — unknown or reserved
/// versions, suites and AAD schemes are rejected with a specific error and there are no silent
/// fallbacks.
/// </summary>
public sealed class CiphertextEnvelopeCodec : ICiphertextEnvelopeCodec
{
    public byte[] Serialize(CiphertextEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        var header = envelope.Header;
        var keyId = header.KeyId.Span;
        var nonce = envelope.Nonce.Span;
        var tag = envelope.Tag.Span;
        var ciphertext = envelope.Ciphertext.Span;

        ValidateForWrite(header, keyId.Length, nonce.Length, tag.Length, ciphertext.Length);

        var total = (long)CiphertextEnvelopeFormat.FixedOverheadLength + keyId.Length + nonce.Length + tag.Length + ciphertext.Length;
        if (total > int.MaxValue)
        {
            throw new ArgumentException("Envelope exceeds the maximum serializable size.", nameof(envelope));
        }

        var buffer = new byte[total];
        var cursor = 0;

        CiphertextEnvelopeFormat.Magic.CopyTo(buffer);
        cursor += CiphertextEnvelopeFormat.MagicLength;

        buffer[cursor++] = header.Version.Value;
        buffer[cursor++] = header.Suite.Value;
        buffer[cursor++] = header.AadScheme.Value;

        buffer[cursor++] = (byte)keyId.Length;
        keyId.CopyTo(buffer.AsSpan(cursor));
        cursor += keyId.Length;

        buffer[cursor++] = (byte)nonce.Length;
        nonce.CopyTo(buffer.AsSpan(cursor));
        cursor += nonce.Length;

        buffer[cursor++] = (byte)tag.Length;
        tag.CopyTo(buffer.AsSpan(cursor));
        cursor += tag.Length;

        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(cursor), (uint)ciphertext.Length);
        cursor += CiphertextEnvelopeFormat.CiphertextLengthFieldLength;

        ciphertext.CopyTo(buffer.AsSpan(cursor));

        return buffer;
    }

    public CiphertextEnvelope Parse(ReadOnlySpan<byte> data)
    {
        if (TryParse(data, out var envelope, out var error))
        {
            return envelope!;
        }

        throw new EnvelopeParseException(error!.Code, error.Message);
    }

    public bool TryParse(ReadOnlySpan<byte> data, out CiphertextEnvelope? envelope, out EnvelopeParseError? error)
    {
        envelope = null;
        error = null;

        if (data.Length < CiphertextEnvelopeFormat.MagicLength)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TooShort, "Buffer is shorter than the magic marker.");
            return false;
        }

        if (!CiphertextEnvelopeFormat.StartsWithMagic(data))
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.InvalidMagic, "Buffer does not start with the envelope magic marker.");
            return false;
        }

        var offset = CiphertextEnvelopeFormat.MagicLength;

        // Version, suite, AAD scheme and key id length are four fixed single bytes.
        if (data.Length < offset + 4)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TooShort, "Buffer ends before the fixed header fields.");
            return false;
        }

        var versionByte = data[offset++];
        if (versionByte != CiphertextEnvelopeFormat.CurrentVersion.Value)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.UnsupportedVersion, $"Envelope version 0x{versionByte:X2} is not supported.");
            return false;
        }

        var suiteByte = data[offset++];
        if (suiteByte == 0 || !CryptoSuiteRegistry.TryGet(new CryptoSuiteId(suiteByte), out var suite))
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.UnknownSuite, $"Crypto suite 0x{suiteByte:X2} is unknown.");
            return false;
        }

        if (!suite!.IsImplemented)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.UnsupportedSuite, $"Crypto suite 0x{suiteByte:X2} is reserved and not implemented.");
            return false;
        }

        var schemeByte = data[offset++];
        if (schemeByte == 0 || !CiphertextEnvelopeFormat.IsKnownAadScheme(new AadSchemeId(schemeByte)))
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.UnknownAadScheme, $"AAD scheme 0x{schemeByte:X2} is unknown.");
            return false;
        }

        if (!CiphertextEnvelopeFormat.IsSupportedAadScheme(new AadSchemeId(schemeByte)))
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.UnsupportedAadScheme, $"AAD scheme 0x{schemeByte:X2} is not active in this release.");
            return false;
        }

        var keyIdLength = data[offset++];
        if (keyIdLength < CiphertextEnvelopeLimits.KeyIdMinLength)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.InvalidKeyIdLength, "Key id length is zero.");
            return false;
        }

        if (offset + keyIdLength > data.Length)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.KeyIdTruncated, $"Declared key id length {keyIdLength} exceeds the remaining buffer.");
            return false;
        }

        var keyIdBytes = data.Slice(offset, keyIdLength);
        offset += keyIdLength;

        if (offset + CiphertextEnvelopeFormat.NonceLengthFieldLength > data.Length)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TooShort, "Buffer ends before the nonce length.");
            return false;
        }

        var nonceLength = data[offset++];
        if (nonceLength != suite.NonceLength)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.InvalidNonceLength, $"Nonce length {nonceLength} does not match suite {suite.Name} (expected {suite.NonceLength}).");
            return false;
        }

        if (offset + nonceLength > data.Length)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.NonceTruncated, $"Declared nonce length {nonceLength} exceeds the remaining buffer.");
            return false;
        }

        var nonceBytes = data.Slice(offset, nonceLength);
        offset += nonceLength;

        if (offset + CiphertextEnvelopeFormat.TagLengthFieldLength > data.Length)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TooShort, "Buffer ends before the tag length.");
            return false;
        }

        var tagLength = data[offset++];
        if (tagLength != suite.TagLength)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.InvalidTagLength, $"Tag length {tagLength} does not match suite {suite.Name} (expected {suite.TagLength}).");
            return false;
        }

        if (offset + tagLength > data.Length)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TagTruncated, $"Declared tag length {tagLength} exceeds the remaining buffer.");
            return false;
        }

        var tagBytes = data.Slice(offset, tagLength);
        offset += tagLength;

        if (offset + CiphertextEnvelopeFormat.CiphertextLengthFieldLength > data.Length)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TooShort, "Buffer ends before the ciphertext length.");
            return false;
        }

        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, CiphertextEnvelopeFormat.CiphertextLengthFieldLength));
        offset += CiphertextEnvelopeFormat.CiphertextLengthFieldLength;

        var remaining = (uint)(data.Length - offset);
        if (ciphertextLength > remaining)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.CiphertextTooLong, $"Declared ciphertext length {ciphertextLength} exceeds the remaining buffer ({remaining}).");
            return false;
        }

        if (ciphertextLength < remaining)
        {
            error = new EnvelopeParseError(EnvelopeParseErrorCode.TrailingData, $"{remaining - ciphertextLength} byte(s) remain after the declared ciphertext.");
            return false;
        }

        var ciphertextBytes = data.Slice(offset, (int)ciphertextLength);

        var header = new CiphertextEnvelopeHeader(
            CiphertextEnvelopeFormat.CurrentVersion,
            new CryptoSuiteId(suiteByte),
            new AadSchemeId(schemeByte),
            KeyId.FromBytes(keyIdBytes));

        envelope = CiphertextEnvelope.Create(header, nonceBytes, tagBytes, ciphertextBytes);
        return true;
    }

    public byte[] CreateAad(CiphertextEnvelopeHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);

        var keyId = header.KeyId.Span;
        var aad = new byte[CiphertextEnvelopeFormat.VersionFieldLength
                           + CiphertextEnvelopeFormat.CryptoSuiteIdFieldLength
                           + CiphertextEnvelopeFormat.AadSchemeIdFieldLength
                           + keyId.Length];

        aad[0] = header.Version.Value;
        aad[1] = header.Suite.Value;
        aad[2] = header.AadScheme.Value;
        keyId.CopyTo(aad.AsSpan(3));

        return aad;
    }

    private static void ValidateForWrite(
        CiphertextEnvelopeHeader header,
        int keyIdLength,
        int nonceLength,
        int tagLength,
        int ciphertextLength)
    {
        if (!CiphertextEnvelopeFormat.IsSupportedVersion(header.Version))
        {
            throw new ArgumentException($"Unsupported envelope version {header.Version}.", nameof(header));
        }

        if (!CryptoSuiteRegistry.TryGet(header.Suite, out var suite))
        {
            throw new ArgumentException($"Unknown crypto suite {header.Suite}.", nameof(header));
        }

        if (!suite!.IsImplemented)
        {
            throw new ArgumentException($"Crypto suite {header.Suite} is reserved and not implemented.", nameof(header));
        }

        if (!CiphertextEnvelopeFormat.IsSupportedAadScheme(header.AadScheme))
        {
            throw new ArgumentException($"Unsupported AAD scheme {header.AadScheme}.", nameof(header));
        }

        if (keyIdLength is < CiphertextEnvelopeLimits.KeyIdMinLength or > CiphertextEnvelopeLimits.KeyIdMaxLength)
        {
            throw new ArgumentException($"Key id length {keyIdLength} is outside the envelope limits.", nameof(header));
        }

        if (nonceLength != suite.NonceLength)
        {
            throw new ArgumentException($"Nonce length {nonceLength} does not match suite {suite.Name} (expected {suite.NonceLength}).", nameof(header));
        }

        if (tagLength != suite.TagLength)
        {
            throw new ArgumentException($"Tag length {tagLength} does not match suite {suite.Name} (expected {suite.TagLength}).", nameof(header));
        }

        if ((uint)ciphertextLength > CiphertextEnvelopeLimits.CiphertextMaxLength)
        {
            throw new ArgumentException("Ciphertext exceeds the maximum length.", nameof(header));
        }
    }
}
