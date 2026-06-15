namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The closed registry of crypto suites the envelope format recognises. Exactly one suite is
/// implemented in the Foundation Release (AES-256-GCM); the others are reserved so their ids can
/// never be repurposed. A suite id absent from this registry is unknown and must be rejected on
/// parse.
/// </summary>
public static class CryptoSuiteRegistry
{
    /// <summary>AES-256-GCM. The implemented Foundation Release suite (12-byte nonce, 16-byte tag).</summary>
    public static CryptoSuiteDefinition Aes256Gcm { get; } =
        new(CryptoSuiteId.Aes256Gcm, "AES-256-GCM", isImplemented: true, nonceLength: 12, tagLength: 16);

    /// <summary>Reserved: AES-256-GCM-SIV. Known but not implemented.</summary>
    public static CryptoSuiteDefinition Aes256GcmSiv { get; } =
        new(CryptoSuiteId.Aes256GcmSiv, "AES-256-GCM-SIV", isImplemented: false, nonceLength: 0, tagLength: 0);

    /// <summary>Reserved: XChaCha20-Poly1305. Known but not implemented.</summary>
    public static CryptoSuiteDefinition XChaCha20Poly1305 { get; } =
        new(CryptoSuiteId.XChaCha20Poly1305, "XChaCha20-Poly1305", isImplemented: false, nonceLength: 0, tagLength: 0);

    /// <summary>Reserved: AES-256-SIV (deterministic). Known but not implemented.</summary>
    public static CryptoSuiteDefinition Aes256SivDeterministic { get; } =
        new(CryptoSuiteId.Aes256SivDeterministic, "AES-256-SIV", isImplemented: false, nonceLength: 0, tagLength: 0);

    private static readonly IReadOnlyList<CryptoSuiteDefinition> AllSuites =
        Array.AsReadOnly(new[] { Aes256Gcm, Aes256GcmSiv, XChaCha20Poly1305, Aes256SivDeterministic });

    /// <summary>All registered suites, implemented and reserved.</summary>
    public static IReadOnlyList<CryptoSuiteDefinition> All => AllSuites;

    /// <summary>Whether the id is a registered suite (implemented or reserved).</summary>
    public static bool IsKnown(CryptoSuiteId id) => TryGet(id, out _);

    /// <summary>Looks up a suite definition by id.</summary>
    public static bool TryGet(CryptoSuiteId id, out CryptoSuiteDefinition? definition)
    {
        foreach (var suite in AllSuites)
        {
            if (suite.Id == id)
            {
                definition = suite;
                return true;
            }
        }

        definition = null;
        return false;
    }

    /// <summary>Returns the suite definition for an id.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The id is not a registered suite.</exception>
    public static CryptoSuiteDefinition Get(CryptoSuiteId id) =>
        TryGet(id, out var definition)
            ? definition!
            : throw new ArgumentOutOfRangeException(nameof(id), id, "Unknown crypto suite id.");
}
