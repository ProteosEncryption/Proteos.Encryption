namespace Proteos.CrmSampleApi.Dtos.Admin;

public sealed record EncryptionAuditResponse(string Entity, string Property, string Classification);

/// <summary>A single encrypted column's stored value, truncated, plus whether it is a Proteos envelope.</summary>
public sealed record RawColumnPreview(string Table, string Column, string StoredValuePreview, bool IsProteosEnvelope);

/// <summary>
/// Proof that the database holds ciphertext: a few encrypted columns shown as truncated Base64
/// envelopes, plus a check that no known seed plaintext leaked into any stored value.
/// </summary>
public sealed record RawDatabasePreviewDto(string Note, bool PlaintextLeakDetected, IReadOnlyList<RawColumnPreview> Columns);

/// <summary>Re-encryption foundation: how many stored values are under an older key than the current one.</summary>
public sealed record ReEncryptionStatusDto(string CurrentKeyId, int ValuesScanned, int ValuesNeedingReEncryption, string Note);
