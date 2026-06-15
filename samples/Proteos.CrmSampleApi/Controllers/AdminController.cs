using Microsoft.AspNetCore.Mvc;
using Proteos.CrmSampleApi.Dtos.Admin;
using Proteos.CrmSampleApi.Services.Admin;

namespace Proteos.CrmSampleApi.Controllers;

[ApiController]
[Route("api/admin")]
public sealed class AdminController : ControllerBase
{
    private readonly IAdminService _admin;

    public AdminController(IAdminService admin) => _admin = admin;

    /// <summary>How every property of the model is classified (encrypted / searchable / plaintext).</summary>
    [HttpGet("encryption-audit")]
    public IReadOnlyList<EncryptionAuditResponse> GetAudit() => _admin.GetAudit();

    /// <summary>Proof from the raw database that sensitive columns hold ciphertext, not plaintext.</summary>
    [HttpGet("raw-preview")]
    public async Task<RawDatabasePreviewDto> GetRawPreview(CancellationToken ct) =>
        await _admin.GetRawPreviewAsync(ct);

    /// <summary>Re-encryption foundation: how many stored values are under an older key than the current one.</summary>
    [HttpGet("reencryption-status")]
    public async Task<ReEncryptionStatusDto> GetReEncryptionStatus(CancellationToken ct) =>
        await _admin.GetReEncryptionStatusAsync(ct);
}
