namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Registry metadata for a crypto suite: its id, a human-readable name, whether it is
/// implemented in the Foundation Release, and the nonce and tag lengths the envelope format
/// expects for it. These lengths are format-validation parameters — they let the parser check a
/// stored envelope against the authenticated suite — not a cryptographic implementation, which
/// is added later.
/// </summary>
public sealed record CryptoSuiteDefinition
{
    /// <summary>The suite's registry id.</summary>
    public CryptoSuiteId Id { get; }

    /// <summary>Human-readable suite name, for diagnostics.</summary>
    public string Name { get; }

    /// <summary>Whether the suite is implemented (active) in the Foundation Release. Only AES-256-GCM is.</summary>
    public bool IsImplemented { get; }

    /// <summary>Expected nonce length in bytes; zero for a reserved suite whose size is unspecified here.</summary>
    public int NonceLength { get; }

    /// <summary>Expected authentication tag length in bytes; zero for a reserved suite whose size is unspecified here.</summary>
    public int TagLength { get; }

    /// <summary>Creates a suite definition.</summary>
    /// <exception cref="ArgumentException">Id is unspecified or name is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// An implemented suite has nonce/tag lengths outside the envelope limits, or a reserved suite has non-zero lengths.
    /// </exception>
    public CryptoSuiteDefinition(CryptoSuiteId id, string name, bool isImplemented, int nonceLength, int tagLength)
    {
        if (id.Value == 0)
        {
            throw new ArgumentException("Crypto suite id must be specified.", nameof(id));
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Crypto suite name must be a non-empty value.", nameof(name));
        }

        if (isImplemented)
        {
            if (nonceLength is < CiphertextEnvelopeLimits.NonceMinLength or > CiphertextEnvelopeLimits.NonceMaxLength)
            {
                throw new ArgumentOutOfRangeException(nameof(nonceLength), nonceLength, "Implemented suite nonce length is outside the envelope limits.");
            }

            if (tagLength is < CiphertextEnvelopeLimits.TagMinLength or > CiphertextEnvelopeLimits.TagMaxLength)
            {
                throw new ArgumentOutOfRangeException(nameof(tagLength), tagLength, "Implemented suite tag length is outside the envelope limits.");
            }
        }
        else if (nonceLength != 0 || tagLength != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonceLength), "A reserved suite must leave nonce and tag lengths unspecified (zero).");
        }

        Id = id;
        Name = name.Trim();
        IsImplemented = isImplemented;
        NonceLength = nonceLength;
        TagLength = tagLength;
    }
}
