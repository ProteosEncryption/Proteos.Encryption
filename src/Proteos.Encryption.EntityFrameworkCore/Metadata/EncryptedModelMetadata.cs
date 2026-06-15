using Microsoft.EntityFrameworkCore.Metadata;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// The single runtime carrier of encryption metadata: the model convention stores the finalized
/// <see cref="EncryptedEntityMetadata"/> on each entity type as a model
/// annotation, and the interceptors and query helpers read it back from here. Because the metadata
/// lives on the (per-DbContext, already cached) EF model, there is no separate cache and no global
/// state, and nothing downstream can tell whether it came from attributes or the fluent API.
/// </summary>
internal static class EncryptedModelMetadata
{
    /// <summary>Annotation holding the finalized <see cref="EncryptedEntityMetadata"/> of an entity type.</summary>
    public const string AnnotationName = "Proteos:Encryption:Metadata";

    /// <summary>Model-level marker set by the convention; its absence means the convention was not applied.</summary>
    public const string ModelAppliedAnnotationName = "Proteos:Encryption:ModelApplied";

    /// <summary>Fluent-API intent: the entity logical name, stored on the entity type during configuration.</summary>
    public const string FluentEntityAnnotationName = "Proteos:Encryption:Fluent:Entity";

    /// <summary>Fluent-API intent: the <see cref="EncryptedPropertyConfiguration"/>, stored on a property during configuration.</summary>
    public const string FluentPropertyAnnotationName = "Proteos:Encryption:Fluent:Property";

    /// <summary>Fluent-API intent: marks a property as deliberately plaintext, stored on the property during configuration.</summary>
    public const string FluentPlaintextAnnotationName = "Proteos:Encryption:Fluent:Plaintext";

    /// <summary>The set of explicitly-plaintext property names of an entity type (attribute and fluent combined).</summary>
    public const string PlaintextAnnotationName = "Proteos:Encryption:Plaintext";

    /// <summary>The finalized <see cref="EncryptionAuditReport"/>, stored on the model by the convention.</summary>
    public const string AuditAnnotationName = "Proteos:Encryption:Audit";

    private static readonly IReadOnlySet<string> NoPlaintext = new HashSet<string>();

    /// <summary>Returns the finalized metadata of an entity type, or null when the type has none.</summary>
    public static EncryptedEntityMetadata? Find(IReadOnlyEntityType entityType) =>
        entityType.FindAnnotation(AnnotationName)?.Value as EncryptedEntityMetadata;

    /// <summary>Returns the explicitly-plaintext property names of an entity type (empty when none).</summary>
    public static IReadOnlySet<string> FindPlaintextProperties(IReadOnlyEntityType entityType) =>
        entityType.FindAnnotation(PlaintextAnnotationName)?.Value as IReadOnlySet<string> ?? NoPlaintext;

    /// <summary>Returns the audit report stored on the model by the convention, or null when not applied.</summary>
    public static EncryptionAuditReport? FindAuditReport(IReadOnlyModel model) =>
        model.FindAnnotation(AuditAnnotationName)?.Value as EncryptionAuditReport;

    /// <summary>
    /// Fails loudly when the encryption interceptors run on a model that never had
    /// <c>UseProteosEncryptionModel()</c> applied — without this guard, encrypted properties would
    /// be written as plaintext silently.
    /// </summary>
    public static void EnsureModelApplied(IReadOnlyModel model)
    {
        if (model.FindAnnotation(ModelAppliedAnnotationName)?.Value is true)
        {
            return;
        }

        throw new InvalidOperationException(
            "Proteos encryption is wired into this DbContext, but UseProteosEncryptionModel() was not called in OnModelCreating. "
            + "Encrypted properties would be stored as plaintext. Call modelBuilder.UseProteosEncryptionModel() after configuring the entities.");
    }
}
