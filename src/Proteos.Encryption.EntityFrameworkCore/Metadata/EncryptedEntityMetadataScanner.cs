using System.Reflection;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Reads encryption intent from a type's attributes. It extracts the entity logical name and one
/// <see cref="EncryptedPropertyConfiguration"/> per encrypted property, then hands them to the
/// shared <see cref="EncryptedMetadataFactory"/> to validate and build the descriptors. The fluent
/// model build reuses the same factory with its own configurations, so attributes and fluent stay
/// behaviour-identical. This reads attributes only; merging with fluent happens at model build.
/// </summary>
public static class EncryptedEntityMetadataScanner
{
    private const BindingFlags PublicInstance = BindingFlags.Public | BindingFlags.Instance;

    /// <summary>Scans a type's attributes into validated metadata (attribute source only).</summary>
    /// <exception cref="ArgumentNullException">The type is null.</exception>
    /// <exception cref="EncryptedEntityMetadataException">The attribute configuration is invalid.</exception>
    public static EncryptedEntityMetadata Scan(Type entityType)
    {
        ArgumentNullException.ThrowIfNull(entityType);

        return EncryptedMetadataFactory.Build(entityType, ReadEntityLogicalName(entityType), ReadAttributeConfigurations(entityType));
    }

    /// <summary>Reads the entity logical name from <see cref="EncryptedEntityAttribute"/> (trimmed; null when absent).</summary>
    internal static string? ReadEntityLogicalName(Type entityType) =>
        entityType.GetCustomAttribute<EncryptedEntityAttribute>(inherit: true)?.Name?.Trim();

    /// <summary>
    /// Reads one configuration per encrypted property, in declaration order. A property carrying
    /// more than one encryption attribute is rejected here, before any descriptor is built.
    /// </summary>
    internal static IReadOnlyList<(PropertyInfo Property, EncryptedPropertyConfiguration Configuration)> ReadAttributeConfigurations(Type entityType)
    {
        var configurations = new List<(PropertyInfo, EncryptedPropertyConfiguration)>();
        foreach (var property in entityType.GetProperties(PublicInstance))
        {
            var attributes = property.GetCustomAttributes<EncryptedAttribute>(inherit: true).ToArray();
            if (attributes.Length == 0)
            {
                continue;
            }

            if (attributes.Length > 1)
            {
                throw new EncryptedEntityMetadataException(
                    $"Property '{entityType.Name}.{property.Name}' has more than one encryption attribute; use exactly one.");
            }

            configurations.Add((property, ToConfiguration(attributes[0])));
        }

        return configurations;
    }

    /// <summary>Reads the property names carrying <see cref="PlaintextAttribute"/>.</summary>
    internal static IReadOnlySet<string> ReadPlaintextProperties(Type entityType)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in entityType.GetProperties(PublicInstance))
        {
            if (property.GetCustomAttribute<PlaintextAttribute>(inherit: true) is not null)
            {
                names.Add(property.Name);
            }
        }

        return names;
    }

    private static EncryptedPropertyConfiguration ToConfiguration(EncryptedAttribute attribute)
    {
        var logicalName = (attribute.Name ?? string.Empty).Trim();

        if (attribute is EncryptedSearchableAttribute searchable)
        {
            var explicitIndex = string.IsNullOrWhiteSpace(searchable.IndexProperty) ? null : searchable.IndexProperty.Trim();
            return new EncryptedPropertyConfiguration(logicalName, IsSearchable: true, searchable.Normalizer, explicitIndex);
        }

        return new EncryptedPropertyConfiguration(logicalName, IsSearchable: false, Normalizer: null, ExplicitIndexProperty: null);
    }
}
