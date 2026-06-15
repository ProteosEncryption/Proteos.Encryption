namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The authenticated metadata of a ciphertext envelope: format version, crypto suite, AAD
/// scheme and key id. Under the Foundation Release AAD scheme, the serialized form of exactly
/// these fields <b>is</b> the Additional Authenticated Data — which is what makes the suite and
/// version bytes tamper-evident and blocks downgrade attacks.
/// </summary>
/// <remarks>
/// Framing details that are not authenticated context — the magic marker and the key-id length
/// prefix — belong to the envelope codec, not to this logical header.
/// </remarks>
public sealed class CiphertextEnvelopeHeader : IEquatable<CiphertextEnvelopeHeader>
{
    /// <summary>Envelope format version.</summary>
    public EnvelopeVersion Version { get; }

    /// <summary>Cryptographic suite used for this envelope.</summary>
    public CryptoSuiteId Suite { get; }

    /// <summary>Scheme by which the AAD is formed.</summary>
    public AadSchemeId AadScheme { get; }

    /// <summary>Opaque identifier of the key used.</summary>
    public KeyId KeyId { get; }

    /// <summary>Creates an envelope header. All metadata fields must be specified (non-default).</summary>
    /// <exception cref="ArgumentNullException">Key id is null.</exception>
    /// <exception cref="ArgumentException">Version, suite or AAD scheme is the default (unspecified) value.</exception>
    public CiphertextEnvelopeHeader(EnvelopeVersion version, CryptoSuiteId suite, AadSchemeId aadScheme, KeyId keyId)
    {
        if (version.Value == 0)
        {
            throw new ArgumentException("Envelope version must be specified.", nameof(version));
        }

        if (suite.Value == 0)
        {
            throw new ArgumentException("Crypto suite must be specified.", nameof(suite));
        }

        if (aadScheme.Value == 0)
        {
            throw new ArgumentException("AAD scheme must be specified.", nameof(aadScheme));
        }

        Version = version;
        Suite = suite;
        AadScheme = aadScheme;
        KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
    }

    public bool Equals(CiphertextEnvelopeHeader? other) =>
        other is not null
        && Version == other.Version
        && Suite == other.Suite
        && AadScheme == other.AadScheme
        && KeyId.Equals(other.KeyId);

    public override bool Equals(object? obj) => Equals(obj as CiphertextEnvelopeHeader);

    public override int GetHashCode() => HashCode.Combine(Version, Suite, AadScheme, KeyId);

    public static bool operator ==(CiphertextEnvelopeHeader? left, CiphertextEnvelopeHeader? right) =>
        left is null ? right is null : left.Equals(right);

    public static bool operator !=(CiphertextEnvelopeHeader? left, CiphertextEnvelopeHeader? right) => !(left == right);
}
