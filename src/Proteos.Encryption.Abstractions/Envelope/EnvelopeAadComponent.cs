namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The header components that form the Additional Authenticated Data under the Foundation
/// Release AAD scheme, listed in serialization order by
/// <see cref="CiphertextEnvelopeFormat.HeaderAadComponents"/>.
/// </summary>
/// <remarks>
/// The magic marker and every length-prefix byte are framing only and are intentionally absent
/// from this enumeration: they are not part of the authenticated context. The key id, by
/// contrast, is bound — moving a value to a different key fails authentication.
/// </remarks>
public enum EnvelopeAadComponent
{
    /// <summary>The envelope format version byte.</summary>
    Version = 1,

    /// <summary>The crypto suite id byte.</summary>
    CryptoSuiteId = 2,

    /// <summary>The AAD scheme id byte.</summary>
    AadSchemeId = 3,

    /// <summary>The key id bytes.</summary>
    KeyId = 4,
}
