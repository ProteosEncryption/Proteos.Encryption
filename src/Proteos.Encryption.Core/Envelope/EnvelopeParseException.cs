using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// Thrown by <see cref="ICiphertextEnvelopeCodec.Parse"/> when a buffer is not a valid envelope.
/// Carries the specific <see cref="EnvelopeParseErrorCode"/>; the message contains structural
/// detail only and no secret material.
/// </summary>
public sealed class EnvelopeParseException : ProteosEncryptionException
{
    /// <summary>The specific parse failure.</summary>
    public EnvelopeParseErrorCode Code { get; }

    public EnvelopeParseException(EnvelopeParseErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }
}
