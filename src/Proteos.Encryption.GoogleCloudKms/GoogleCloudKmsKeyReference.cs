using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// A validated Google Cloud KMS key reference — the key-encryption-key (KEK) that wraps tenant master
/// keys. It is parsed from the full <c>CryptoKey</c> resource name
/// <c>projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}</c> and exposes
/// its parts. A symmetric <c>ENCRYPT_DECRYPT</c> CryptoKey is expected: KMS picks the primary version on
/// encrypt and the matching version on decrypt, so a version-qualified
/// (<c>.../cryptoKeyVersions/{version}</c>) name is deliberately rejected.
/// </summary>
public sealed class GoogleCloudKmsKeyReference
{
    private GoogleCloudKmsKeyReference(string keyName, string projectId, string locationId, string keyRingId, string cryptoKeyId)
    {
        KeyName = keyName;
        ProjectId = projectId;
        LocationId = locationId;
        KeyRingId = keyRingId;
        CryptoKeyId = cryptoKeyId;
    }

    /// <summary>The full CryptoKey resource name, exactly as Cloud KMS consumes it.</summary>
    public string KeyName { get; }

    /// <summary>The Google Cloud project id.</summary>
    public string ProjectId { get; }

    /// <summary>The KMS location id (for example <c>global</c> or <c>europe-west3</c>).</summary>
    public string LocationId { get; }

    /// <summary>The key ring id.</summary>
    public string KeyRingId { get; }

    /// <summary>The CryptoKey id.</summary>
    public string CryptoKeyId { get; }

    /// <summary>Parses and validates a Cloud KMS CryptoKey resource name.</summary>
    /// <exception cref="ArgumentException">
    /// The value is null/whitespace, not a CryptoKey resource name, or a version-qualified name.
    /// </exception>
    public static GoogleCloudKmsKeyReference Parse(string keyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);

        var value = keyName.Trim();
        var segments = value.Split('/');

        // Reject a version-qualified name positionally: a valid CryptoKey path is 8 segments; appending
        // '/cryptoKeyVersions/<version>' makes it 10 with 'cryptoKeyVersions' at index 8. Only that exact
        // shape counts as version-qualified, so a CryptoKey legitimately named 'cryptoKeyVersions' is not
        // mistaken for one.
        if (segments.Length == 10 && segments[8] == "cryptoKeyVersions" && IsCryptoKeyPath(segments))
        {
            throw new ArgumentException(
                $"'{keyName}' is a CryptoKeyVersion resource name. Provide the CryptoKey resource name without the '/cryptoKeyVersions/<version>' suffix; the symmetric provider lets KMS select the version.",
                nameof(keyName));
        }

        // Expected: projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k} — exactly 8 segments.
        if (segments.Length != 8 || !IsCryptoKeyPath(segments))
        {
            throw new ArgumentException(
                $"'{keyName}' is not a Cloud KMS CryptoKey resource name. Expected 'projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<cryptoKey>'.",
                nameof(keyName));
        }

        return new GoogleCloudKmsKeyReference(value, segments[1], segments[3], segments[5], segments[7]);
    }

    /// <summary>
    /// Interprets a vendor-neutral <see cref="ProviderKeyReference"/> as a Google Cloud KMS key
    /// reference. The reference must be for <see cref="KeyProviderKind.GoogleKms"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">The reference is null.</exception>
    /// <exception cref="ArgumentException">The reference is for another provider, or is not a valid CryptoKey resource name.</exception>
    public static GoogleCloudKmsKeyReference FromProviderKeyReference(ProviderKeyReference reference)
    {
        ArgumentNullException.ThrowIfNull(reference);

        if (reference.Provider != KeyProviderKind.GoogleKms)
        {
            throw new ArgumentException(
                $"Provider key reference is for '{reference.Provider}', not {KeyProviderKind.GoogleKms}.",
                nameof(reference));
        }

        return Parse(reference.Reference);
    }

    /// <summary>Returns the full CryptoKey resource name.</summary>
    public override string ToString() => KeyName;

    // Checks the first eight segments form a CryptoKey path:
    // projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>. Length is checked by the caller.
    private static bool IsCryptoKeyPath(string[] segments) =>
        segments.Length >= 8 &&
        segments[0] == "projects" &&
        segments[2] == "locations" &&
        segments[4] == "keyRings" &&
        segments[6] == "cryptoKeys" &&
        IsValidSegment(segments[1]) &&
        IsValidSegment(segments[3]) &&
        IsValidSegment(segments[5]) &&
        IsValidSegment(segments[7]);

    // KMS project / location / key-ring / key ids are non-empty and use only [A-Za-z0-9_-].
    private static bool IsValidSegment(string segment)
    {
        if (segment.Length == 0)
        {
            return false;
        }

        foreach (var c in segment)
        {
            var ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-' or '_';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }
}
