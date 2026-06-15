using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.AwsKms;

/// <summary>
/// A validated AWS KMS key reference — the customer master key (CMK) that wraps tenant master keys.
/// AWS KMS accepts four equivalent forms for a key, all supported here: a key ARN, an alias ARN, a bare
/// key id, or a bare alias name. The reference is passed verbatim to KMS <c>Encrypt</c>/<c>Decrypt</c> as
/// the <c>KeyId</c>; passing it to <c>Decrypt</c> as well pins which key may unwrap, the recommended,
/// fail-closed behaviour for symmetric keys. Prefer a key ARN or key id for stability; an alias resolves
/// at call time.
/// </summary>
public sealed class AwsKmsKeyReference
{
    private AwsKmsKeyReference(string keyId, AwsKmsKeyReferenceKind kind, string? region)
    {
        KeyId = keyId;
        Kind = kind;
        Region = region;
    }

    /// <summary>The reference exactly as AWS KMS consumes it (ARN, key id, alias ARN or alias name).</summary>
    public string KeyId { get; }

    /// <summary>Which of the four supported forms this reference is.</summary>
    public AwsKmsKeyReferenceKind Kind { get; }

    /// <summary>The region, when it can be derived from an ARN; otherwise null (region must be configured).</summary>
    public string? Region { get; }

    /// <summary>Parses and validates an AWS KMS key reference.</summary>
    /// <exception cref="ArgumentException">The value is not a recognised KMS key reference.</exception>
    public static AwsKmsKeyReference Parse(string keyReference)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyReference);
        var value = keyReference.Trim();

        if (value.StartsWith("arn:", StringComparison.Ordinal))
        {
            return ParseArn(value);
        }

        if (value.StartsWith("alias/", StringComparison.Ordinal))
        {
            if (value.Length <= "alias/".Length)
            {
                throw new ArgumentException($"'{keyReference}' is an empty KMS alias name.", nameof(keyReference));
            }

            return new AwsKmsKeyReference(value, AwsKmsKeyReferenceKind.AliasName, region: null);
        }

        // Otherwise a bare key id. KMS key ids contain no whitespace, ':' or '/'.
        if (value.IndexOfAny([' ', '\t', ':', '/']) >= 0)
        {
            throw new ArgumentException(
                $"'{keyReference}' is not a recognised KMS key reference. Expected a key ARN, an alias ARN, a key id, or 'alias/<name>'.",
                nameof(keyReference));
        }

        return new AwsKmsKeyReference(value, AwsKmsKeyReferenceKind.KeyId, region: null);
    }

    /// <summary>
    /// Interprets a vendor-neutral <see cref="ProviderKeyReference"/> as an AWS KMS key reference. The
    /// reference must be for <see cref="KeyProviderKind.AwsKms"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">The reference is null.</exception>
    /// <exception cref="ArgumentException">The reference is for another provider, or is not a valid KMS reference.</exception>
    public static AwsKmsKeyReference FromProviderKeyReference(ProviderKeyReference reference)
    {
        ArgumentNullException.ThrowIfNull(reference);

        if (reference.Provider != KeyProviderKind.AwsKms)
        {
            throw new ArgumentException(
                $"Provider key reference is for '{reference.Provider}', not {KeyProviderKind.AwsKms}.",
                nameof(reference));
        }

        return Parse(reference.Reference);
    }

    /// <summary>Returns the key reference as KMS consumes it.</summary>
    public override string ToString() => KeyId;

    private static AwsKmsKeyReference ParseArn(string arn)
    {
        // arn:partition:service:region:account-id:resource  (resource may contain '/', never ':').
        var parts = arn.Split(':', 6);
        if (parts.Length != 6 || parts[0] != "arn" || !string.Equals(parts[2], "kms", StringComparison.Ordinal))
        {
            throw new ArgumentException($"'{arn}' is not a valid AWS KMS ARN.", nameof(arn));
        }

        var region = parts[3];
        if (string.IsNullOrWhiteSpace(region))
        {
            throw new ArgumentException($"'{arn}' is missing a region.", nameof(arn));
        }

        var resource = parts[5];
        var kind = resource.StartsWith("alias/", StringComparison.Ordinal)
            ? AwsKmsKeyReferenceKind.AliasArn
            : resource.StartsWith("key/", StringComparison.Ordinal)
                ? AwsKmsKeyReferenceKind.KeyArn
                : throw new ArgumentException($"'{arn}' is not a KMS key or alias ARN.", nameof(arn));

        if (resource.IndexOf('/') == resource.Length - 1)
        {
            throw new ArgumentException($"'{arn}' has an empty key or alias name.", nameof(arn));
        }

        return new AwsKmsKeyReference(arn, kind, region);
    }
}
