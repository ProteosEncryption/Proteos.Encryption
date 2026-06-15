namespace Proteos.Encryption.AwsKms;

/// <summary>
/// Options for registering the AWS KMS key provider. <see cref="KeyId"/> is the KMS key reference — a
/// key ARN, an alias ARN, a bare key id, or an <c>alias/&lt;name&gt;</c>. <see cref="Region"/> is
/// optional: when not set, the region is taken from the key ARN if present, otherwise from the AWS SDK's
/// default resolution (for example the <c>AWS_REGION</c> environment variable or the shared config).
/// AWS credentials always come from the SDK's default credential chain; none is forced here.
/// </summary>
public sealed class AwsKmsOptions
{
    /// <summary>
    /// The KMS key reference (key ARN, alias ARN, key id, or <c>alias/&lt;name&gt;</c>). Prefer a key ARN
    /// or key id for stability; an alias resolves at call time.
    /// </summary>
    public string? KeyId { get; set; }

    /// <summary>
    /// The AWS region, for example <c>eu-central-1</c>. Optional when the key reference is an ARN (which
    /// carries the region) or the region is available from the AWS SDK default chain.
    /// </summary>
    public string? Region { get; set; }
}
