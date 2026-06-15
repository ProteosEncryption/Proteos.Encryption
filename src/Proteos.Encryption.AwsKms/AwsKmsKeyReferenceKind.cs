namespace Proteos.Encryption.AwsKms;

/// <summary>The recognised shapes of an AWS KMS key reference.</summary>
public enum AwsKmsKeyReferenceKind
{
    /// <summary>A key ARN: <c>arn:aws:kms:&lt;region&gt;:&lt;account&gt;:key/&lt;key-id&gt;</c>.</summary>
    KeyArn,

    /// <summary>An alias ARN: <c>arn:aws:kms:&lt;region&gt;:&lt;account&gt;:alias/&lt;name&gt;</c>.</summary>
    AliasArn,

    /// <summary>A bare key id (for example a UUID, or a multi-Region <c>mrk-</c> id).</summary>
    KeyId,

    /// <summary>A bare alias name: <c>alias/&lt;name&gt;</c>.</summary>
    AliasName,
}
