namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The matching semantics a blind index provides. Distinct from <see cref="KeyPurpose"/>, which
/// is about key derivation; this describes what kind of query the index answers.
/// </summary>
public enum BlindIndexPurpose
{
    /// <summary>Exact-match lookup via a truncated keyed hash of the normalized value. The Foundation Release semantics.</summary>
    ExactMatch = 1,
}
