namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The cryptographic purpose a derived subkey serves. Encodes the mandatory domain
/// separation between encryption keys and blind-index keys: a single Tenant Master Key
/// never produces the same subkey for two different purposes.
/// </summary>
/// <remarks>
/// The values here are the in-process representation. The canonical, persisted token that
/// feeds the HKDF <c>info</c> input (for the Foundation Release: <c>enc</c> / <c>idx</c>) is
/// owned by the crypto core, so that the derivation contract has a single source of truth.
/// </remarks>
public enum KeyPurpose
{
    /// <summary>Subkey used for authenticated encryption of a field value (HKDF purpose <c>enc</c>).</summary>
    Encryption = 1,

    /// <summary>Subkey used to compute a blind index for exact-match search (HKDF purpose <c>idx</c>).</summary>
    BlindIndex = 2,
}
