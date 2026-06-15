using Microsoft.EntityFrameworkCore.Metadata;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Access to the encryption audit report. Lives in the <c>Microsoft.EntityFrameworkCore</c> namespace
/// so it sits next to <c>DbContext</c>.
/// </summary>
public static class ProteosEncryptionAuditExtensions
{
    /// <summary>
    /// Returns the encryption audit report for this context's model: every string/byte[] property and
    /// its classification (encrypted, searchable, plaintext or unclassified). Computed once by
    /// <c>UseProteosEncryptionModel()</c>; recomputed on the fly if the convention was not applied.
    /// </summary>
    /// <exception cref="ArgumentNullException">The context is null.</exception>
    public static EncryptionAuditReport GetEncryptionAuditReport(this DbContext dbContext)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        return dbContext.Model.GetEncryptionAuditReport();
    }

    /// <summary>Returns the encryption audit report for a model. See <see cref="GetEncryptionAuditReport(DbContext)"/>.</summary>
    /// <exception cref="ArgumentNullException">The model is null.</exception>
    public static EncryptionAuditReport GetEncryptionAuditReport(this IReadOnlyModel model)
    {
        ArgumentNullException.ThrowIfNull(model);
        return EncryptedModelMetadata.FindAuditReport(model) ?? EncryptionAuditReport.Create(model);
    }
}
