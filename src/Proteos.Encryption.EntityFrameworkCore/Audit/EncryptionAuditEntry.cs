namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// One row of the encryption audit: a single string/byte[] property of an entity and how it is
/// classified. Blind index columns (shadow or explicit) are not audited — they are internal.
/// </summary>
public sealed record EncryptionAuditEntry(
    Type EntityClrType,
    string? EntityLogicalName,
    string PropertyName,
    Type PropertyClrType,
    EncryptionClassification Classification)
{
    /// <summary>The entity and property as <c>"Entity.Property"</c>, e.g. <c>"Customer.Email"</c>.</summary>
    public string Path => $"{EntityClrType.Name}.{PropertyName}";
}
