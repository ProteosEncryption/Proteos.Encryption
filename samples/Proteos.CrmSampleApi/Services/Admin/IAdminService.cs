using Proteos.CrmSampleApi.Dtos.Admin;

namespace Proteos.CrmSampleApi.Services.Admin;

public interface IAdminService
{
    /// <summary>Classification of every string/byte[] property in the model.</summary>
    IReadOnlyList<EncryptionAuditResponse> GetAudit();

    /// <summary>Reads raw stored values straight from SQLite to prove the database holds ciphertext.</summary>
    Task<RawDatabasePreviewDto> GetRawPreviewAsync(CancellationToken ct);

    /// <summary>Re-encryption foundation: how many stored values are under an older key than the current one.</summary>
    Task<ReEncryptionStatusDto> GetReEncryptionStatusAsync(CancellationToken ct);
}
