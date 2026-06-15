namespace Proteos.SampleApi.Dtos;

/// <summary>
/// One row of the encryption audit: how a single property is classified. Built from the Proteos
/// audit report (<c>db.GetEncryptionAuditReport()</c>), which is derived from the EF model.
/// Classification is one of: Encrypted, EncryptedSearchable, Plaintext, Unclassified.
/// </summary>
public sealed record EncryptionAuditResponse(
    string Entity,
    string Property,
    string Classification);
