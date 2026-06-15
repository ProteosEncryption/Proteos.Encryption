using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Fluent counterpart of <see cref="EncryptedEntityAttribute"/>. Declares an entity's stable
/// logical name on the EF model; <c>UseProteosEncryptionModel()</c> later reads it back, merges it
/// with any attribute and builds the same metadata. Lives in the <c>Microsoft.EntityFrameworkCore</c>
/// namespace so it sits next to EF's own <c>EntityTypeBuilder</c> methods.
/// </summary>
public static class ProteosEncryptionEntityTypeBuilderExtensions
{
    /// <summary>
    /// Declares the stable entity logical name (for example <c>"customer"</c>), the fluent
    /// equivalent of <c>[EncryptedEntity("...")]</c>. Returns the builder so property configuration
    /// can be chained.
    /// </summary>
    /// <exception cref="ArgumentNullException">The builder is null.</exception>
    /// <exception cref="ArgumentException">The logical name is null or whitespace.</exception>
    public static EntityTypeBuilder<TEntity> IsEncryptedEntity<TEntity>(this EntityTypeBuilder<TEntity> entityTypeBuilder, string entityLogicalName)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(entityTypeBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(entityLogicalName);

        entityTypeBuilder.Metadata.SetAnnotation(EncryptedModelMetadata.FluentEntityAnnotationName, entityLogicalName.Trim());
        return entityTypeBuilder;
    }
}
