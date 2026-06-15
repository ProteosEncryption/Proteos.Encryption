namespace Proteos.Encryption.Core;

/// <summary>
/// A structured parse failure: a machine-readable <see cref="Code"/> and a human-readable
/// <see cref="Message"/>. The message describes structure only (offsets, declared and expected
/// lengths, field names) and never echoes key, nonce, tag or ciphertext bytes.
/// </summary>
public sealed record EnvelopeParseError(EnvelopeParseErrorCode Code, string Message);
