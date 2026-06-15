using System.Reflection;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Finalizes the Proteos encryption model. For every entity it merges the attribute and fluent
/// configuration into one set of descriptors (a conflicting attribute/fluent setting is a hard
/// error), configures each searchable property's blind index column — an EF shadow property
/// (<c>byte[]</c>, nullable, max length 32) by default, or a named CLR property — with a non-unique
/// database index, and stores the finalized metadata on the entity type. After this runs the model
/// is the single source of encryption metadata; the interceptors and query helpers read it from
/// there without knowing whether it came from attributes or fluent. It does not remap the encrypted
/// value columns and performs no runtime encryption — that is the interceptor's job.
/// </summary>
public static class ProteosEncryptionModelBuilderExtensions
{
    private const int BlindIndexByteLength = 32;
    private const BindingFlags PublicInstance = BindingFlags.Public | BindingFlags.Instance;

    /// <summary>
    /// Call from <c>OnModelCreating</c> after the entities (and any fluent encryption configuration)
    /// are set up. Fails at model build on any invalid or conflicting encryption metadata.
    /// </summary>
    /// <exception cref="ArgumentNullException">The model builder is null.</exception>
    /// <exception cref="EncryptedEntityMetadataException">The encryption metadata of an entity is invalid or conflicting.</exception>
    public static ModelBuilder UseProteosEncryptionModel(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            var clrType = entityType.ClrType;
            var metadata = EncryptedMetadataFactory.Build(
                clrType,
                MergeEntityLogicalName(clrType, entityType),
                MergeConfigurations(clrType, entityType));

            var plaintext = GatherPlaintextProperties(clrType, entityType);
            ValidateNoEncryptedPlaintextConflict(clrType, metadata, plaintext);

            if (metadata.HasEncryptedProperties)
            {
                var entityBuilder = modelBuilder.Entity(clrType);
                foreach (var descriptor in metadata.Properties)
                {
                    if (descriptor.IsSearchable)
                    {
                        ConfigureBlindIndex(entityBuilder, descriptor);
                    }
                }

                entityType.SetAnnotation(EncryptedModelMetadata.AnnotationName, metadata);
            }

            if (plaintext.Count > 0)
            {
                entityType.SetAnnotation(EncryptedModelMetadata.PlaintextAnnotationName, plaintext);
            }
        }

        // Marker for the save interceptor: its absence means the convention never ran, which would
        // otherwise let encrypted properties be written as plaintext.
        modelBuilder.Model.SetAnnotation(EncryptedModelMetadata.ModelAppliedAnnotationName, true);

        // The audit reads the annotations set above, so it is built once everything is finalized.
        modelBuilder.Model.SetAnnotation(EncryptedModelMetadata.AuditAnnotationName, EncryptionAuditReport.Create(modelBuilder.Model));
        return modelBuilder;
    }

    private static IReadOnlySet<string> GatherPlaintextProperties(Type clrType, IMutableEntityType entityType)
    {
        var plaintext = new HashSet<string>(EncryptedEntityMetadataScanner.ReadPlaintextProperties(clrType), StringComparer.Ordinal);
        foreach (var property in entityType.GetProperties())
        {
            if (property.FindAnnotation(EncryptedModelMetadata.FluentPlaintextAnnotationName)?.Value is true)
            {
                plaintext.Add(property.Name);
            }
        }

        return plaintext;
    }

    private static void ValidateNoEncryptedPlaintextConflict(Type clrType, EncryptedEntityMetadata metadata, IReadOnlySet<string> plaintext)
    {
        foreach (var descriptor in metadata.Properties)
        {
            if (plaintext.Contains(descriptor.PropertyName))
            {
                throw new EncryptedEntityMetadataException(
                    $"Property '{clrType.Name}.{descriptor.PropertyName}' is marked both encrypted and plaintext. Choose exactly one classification.");
            }
        }
    }

    private static IReadOnlyList<(PropertyInfo Property, EncryptedPropertyConfiguration Configuration)> MergeConfigurations(Type clrType, IMutableEntityType entityType)
    {
        var attributes = EncryptedEntityMetadataScanner.ReadAttributeConfigurations(clrType)
            .ToDictionary(item => item.Property, item => item.Configuration);

        var merged = new List<(PropertyInfo, EncryptedPropertyConfiguration)>();
        foreach (var property in clrType.GetProperties(PublicInstance))
        {
            var attribute = attributes.GetValueOrDefault(property);
            var fluent = ReadFluentPropertyConfiguration(entityType, property.Name);
            var reconciled = Reconcile(clrType, property, attribute, fluent);
            if (reconciled is not null)
            {
                merged.Add((property, reconciled));
            }
        }

        return merged;
    }

    private static EncryptedPropertyConfiguration? Reconcile(Type clrType, PropertyInfo property, EncryptedPropertyConfiguration? attribute, EncryptedPropertyConfiguration? fluent)
    {
        if (attribute is null)
        {
            return fluent;
        }

        if (fluent is null || attribute == fluent)
        {
            return attribute;
        }

        throw new EncryptedEntityMetadataException(
            $"Property '{clrType.Name}.{property.Name}' is configured by both an attribute and the fluent API with different settings "
            + $"(attribute: {Describe(attribute)}; fluent: {Describe(fluent)}). Configure it in one place, or make both identical.");
    }

    private static string? MergeEntityLogicalName(Type clrType, IMutableEntityType entityType)
    {
        var attribute = EncryptedEntityMetadataScanner.ReadEntityLogicalName(clrType);
        var fluent = entityType.FindAnnotation(EncryptedModelMetadata.FluentEntityAnnotationName)?.Value as string;

        if (attribute is null)
        {
            return fluent;
        }

        if (fluent is null || string.Equals(attribute, fluent, StringComparison.Ordinal))
        {
            return attribute;
        }

        throw new EncryptedEntityMetadataException(
            $"Entity '{clrType.Name}' has a different entity logical name in its attribute ('{attribute}') and the fluent API ('{fluent}'). Use one, or make them identical.");
    }

    private static EncryptedPropertyConfiguration? ReadFluentPropertyConfiguration(IMutableEntityType entityType, string propertyName) =>
        entityType.FindProperty(propertyName)?.FindAnnotation(EncryptedModelMetadata.FluentPropertyAnnotationName)?.Value as EncryptedPropertyConfiguration;

    private static string Describe(EncryptedPropertyConfiguration configuration)
    {
        if (!configuration.IsSearchable)
        {
            return $"encrypted '{configuration.PropertyLogicalName}'";
        }

        var index = configuration.ExplicitIndexProperty is null ? "shadow index" : $"index '{configuration.ExplicitIndexProperty}'";
        return $"searchable '{configuration.PropertyLogicalName}', normalizer {configuration.Normalizer}, {index}";
    }

    private static void ConfigureBlindIndex(EntityTypeBuilder entityBuilder, EncryptedPropertyDescriptor descriptor)
    {
        var indexProperty = descriptor.IndexPropertyName!;

        if (descriptor.IndexIsShadow)
        {
            entityBuilder.Property<byte[]>(indexProperty)
                .IsRequired(false)
                .HasMaxLength(BlindIndexByteLength);
        }

        entityBuilder.HasIndex(indexProperty).IsUnique(false);
    }
}
