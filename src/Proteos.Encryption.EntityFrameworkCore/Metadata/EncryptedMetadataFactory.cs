using System.Reflection;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Turns source-agnostic <see cref="EncryptedPropertyConfiguration"/> intent into validated
/// <see cref="EncryptedEntityMetadata"/>. This is the single place that builds scopes, checks
/// property types, validates searchable/normalizer rules and resolves the blind index column —
/// shared by the attribute scanner and the fluent model build, so both paths validate identically
/// and yield identical descriptors.
/// </summary>
internal static class EncryptedMetadataFactory
{
    private const string ShadowIndexSuffix = "Index";
    private const BindingFlags PublicInstance = BindingFlags.Public | BindingFlags.Instance;

    public static EncryptedEntityMetadata Build(
        Type entityType,
        string? entityLogicalName,
        IReadOnlyList<(PropertyInfo Property, EncryptedPropertyConfiguration Configuration)> configurations)
    {
        if (configurations.Count == 0)
        {
            return new EncryptedEntityMetadata(entityType, entityLogicalName, []);
        }

        if (string.IsNullOrEmpty(entityLogicalName))
        {
            throw new EncryptedEntityMetadataException(
                $"Entity '{entityType.Name}' has encrypted properties but is missing an entity logical name; set [EncryptedEntity(\"...\")] or call .IsEncryptedEntity(\"...\").");
        }

        var descriptors = new List<EncryptedPropertyDescriptor>(configurations.Count);
        foreach (var (property, configuration) in configurations)
        {
            descriptors.Add(BuildDescriptor(entityType, entityLogicalName, property, configuration));
        }

        return new EncryptedEntityMetadata(entityType, entityLogicalName, descriptors);
    }

    private static EncryptedPropertyDescriptor BuildDescriptor(Type entityType, string entityLogicalName, PropertyInfo property, EncryptedPropertyConfiguration configuration)
    {
        if (!property.CanRead || !property.CanWrite)
        {
            throw new EncryptedEntityMetadataException(
                $"Encrypted property '{entityType.Name}.{property.Name}' must be readable and writable.");
        }

        if (!IsSupportedValueType(property.PropertyType))
        {
            throw new EncryptedEntityMetadataException(
                $"Encrypted property '{entityType.Name}.{property.Name}' has unsupported type '{property.PropertyType.Name}'. Supported types are string and byte[].");
        }

        var scope = BuildScope(entityType, property, entityLogicalName, configuration.PropertyLogicalName);

        if (!configuration.IsSearchable)
        {
            return new EncryptedPropertyDescriptor(property.Name, property.PropertyType, configuration.PropertyLogicalName, scope, IsSearchable: false, IndexPropertyName: null, IndexIsShadow: false, NormalizerKind: null);
        }

        if (property.PropertyType != typeof(string))
        {
            throw new EncryptedEntityMetadataException(
                $"Searchable property '{entityType.Name}.{property.Name}' must be of type string in this release.");
        }

        if (configuration.Normalizer is not { } normalizer)
        {
            throw new EncryptedEntityMetadataException(
                $"Searchable property '{entityType.Name}.{property.Name}' is missing a normalizer.");
        }

        if (!Enum.IsDefined(normalizer))
        {
            throw new EncryptedEntityMetadataException(
                $"Searchable property '{entityType.Name}.{property.Name}' uses an unsupported normalizer.");
        }

        var (indexName, isShadow) = ResolveIndex(entityType, property, configuration.ExplicitIndexProperty);

        return new EncryptedPropertyDescriptor(property.Name, property.PropertyType, configuration.PropertyLogicalName, scope, IsSearchable: true, indexName, isShadow, normalizer);
    }

    private static EncryptedDataScope BuildScope(Type entityType, PropertyInfo property, string entityLogicalName, string propertyLogicalName)
    {
        if (propertyLogicalName.Length == 0)
        {
            throw new EncryptedEntityMetadataException(
                $"Encrypted property '{entityType.Name}.{property.Name}' requires a non-empty logical name, e.g. [Encrypted(\"email\")] or .IsEncrypted(\"email\").");
        }

        try
        {
            return new EncryptedDataScope(new LogicalName(entityLogicalName), new LogicalName(propertyLogicalName));
        }
        catch (ArgumentException exception)
        {
            throw new EncryptedEntityMetadataException(
                $"Invalid logical name for '{entityType.Name}.{property.Name}': {exception.Message}");
        }
    }

    private static (string Name, bool IsShadow) ResolveIndex(Type entityType, PropertyInfo property, string? explicitIndexProperty)
    {
        if (!string.IsNullOrEmpty(explicitIndexProperty))
        {
            if (string.Equals(explicitIndexProperty, property.Name, StringComparison.Ordinal))
            {
                throw new EncryptedEntityMetadataException(
                    $"Searchable property '{entityType.Name}.{property.Name}' must not use itself as its IndexProperty.");
            }

            var indexProperty = entityType.GetProperty(explicitIndexProperty, PublicInstance)
                ?? throw new EncryptedEntityMetadataException(
                    $"Index property '{entityType.Name}.{explicitIndexProperty}' for '{property.Name}' does not exist.");

            ValidateIndexClrProperty(entityType, indexProperty);
            return (explicitIndexProperty, false);
        }

        var shadowName = property.Name + ShadowIndexSuffix;
        var existing = entityType.GetProperty(shadowName, PublicInstance);
        if (existing is not null)
        {
            // A CLR property already occupies the shadow name; it must be a compatible blind index column.
            ValidateIndexClrProperty(entityType, existing);
            return (shadowName, false);
        }

        return (shadowName, true);
    }

    private static void ValidateIndexClrProperty(Type entityType, PropertyInfo indexProperty)
    {
        if (indexProperty.PropertyType != typeof(byte[]))
        {
            throw new EncryptedEntityMetadataException(
                $"Index property '{entityType.Name}.{indexProperty.Name}' must be of type byte[].");
        }

        if (!indexProperty.CanRead || !indexProperty.CanWrite)
        {
            throw new EncryptedEntityMetadataException(
                $"Index property '{entityType.Name}.{indexProperty.Name}' must be readable and writable.");
        }
    }

    private static bool IsSupportedValueType(Type type) => type == typeof(string) || type == typeof(byte[]);
}
