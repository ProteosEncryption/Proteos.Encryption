using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Decides whether a value scheduled for encryption is in fact already a Proteos ciphertext
/// envelope. Detection is structural and deterministic: the bytes must parse as a complete, valid
/// envelope via <see cref="ICiphertextEnvelopeCodec.TryParse"/> — magic marker, a supported
/// version/suite/AAD scheme, exact key-id/nonce/tag lengths and no trailing bytes. It is the same
/// criterion the format already uses to recognise ciphertext on read.
/// </summary>
/// <remarks>
/// This is never a "looks like Base64" guess. A genuine plaintext is only ever rejected if it is,
/// byte for byte, a structurally valid envelope (for a string property: a Base64 encoding of one),
/// which is not a meaningful human value. Empty ciphertext still makes a 17-byte envelope, so a
/// short or partial buffer fails the parse and counts as plaintext.
/// </remarks>
internal static class EncryptedEnvelopeDetector
{
    /// <summary>
    /// Returns true when <paramref name="value"/> already holds a Proteos envelope. String properties
    /// store the envelope Base64-encoded, so the string must first decode as Base64 and then parse;
    /// <c>byte[]</c> properties store the raw envelope and are parsed directly.
    /// </summary>
    public static bool IsEncryptedEnvelope(object value, bool isStringProperty, ICiphertextEnvelopeCodec codec)
    {
        if (isStringProperty)
        {
            return value is string text
                && TryDecodeBase64(text, out var decoded)
                && codec.TryParse(decoded, out _, out _);
        }

        return value is byte[] bytes && codec.TryParse(bytes, out _, out _);
    }

    private static bool TryDecodeBase64(string value, out ReadOnlySpan<byte> decoded)
    {
        // Strict Base64 decode without exceptions for control flow. The destination is sized to the
        // theoretical maximum (4 chars -> 3 bytes), so a failure means "not valid Base64", never
        // "buffer too small".
        var buffer = new byte[(value.Length / 4) * 3 + 3];
        if (Convert.TryFromBase64String(value, buffer, out var written))
        {
            decoded = buffer.AsSpan(0, written);
            return true;
        }

        decoded = default;
        return false;
    }
}
