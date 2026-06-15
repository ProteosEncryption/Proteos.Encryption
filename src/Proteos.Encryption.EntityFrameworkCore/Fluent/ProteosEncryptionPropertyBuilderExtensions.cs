using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Fluent counterpart of <see cref="EncryptedAttribute"/>, <see cref="EncryptedSearchableAttribute"/>
/// and <see cref="EncryptedEmailAttribute"/>. Each method records the property's encryption intent
/// on the EF model as an <see cref="EncryptedPropertyConfiguration"/>; <c>UseProteosEncryptionModel()</c>
/// later reads it back, merges it with any attribute (a different configuration is a hard error)
/// and builds the same descriptor through the shared metadata factory. Lives next to EF's own
/// <c>PropertyBuilder</c> methods.
/// </summary>
public static class ProteosEncryptionPropertyBuilderExtensions
{
    /// <summary>
    /// Marks the property as stored encrypted (string or <c>byte[]</c>), the fluent equivalent of
    /// <c>[Encrypted("...")]</c>.
    /// </summary>
    /// <exception cref="ArgumentNullException">The builder is null.</exception>
    /// <exception cref="ArgumentException">The logical name is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">The property already has a fluent encryption configuration.</exception>
    public static PropertyBuilder IsEncrypted(this PropertyBuilder propertyBuilder, string propertyLogicalName)
    {
        ArgumentNullException.ThrowIfNull(propertyBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(propertyLogicalName);

        SetConfiguration(propertyBuilder, new EncryptedPropertyConfiguration(propertyLogicalName.Trim(), IsSearchable: false, Normalizer: null, ExplicitIndexProperty: null));
        return propertyBuilder;
    }

    /// <summary>
    /// Marks the property as stored encrypted and searchable via a blind index, the fluent
    /// equivalent of <c>[EncryptedSearchable("...")]</c>. Omit <paramref name="indexProperty"/> for
    /// an automatic shadow index column. Searchable properties must be of type string; a non-string
    /// property is rejected at model build, just as with the attribute.
    /// </summary>
    /// <exception cref="ArgumentNullException">The builder is null.</exception>
    /// <exception cref="ArgumentException">The logical name is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">The property already has a fluent encryption configuration.</exception>
    public static PropertyBuilder IsEncryptedSearchable(
        this PropertyBuilder propertyBuilder,
        string propertyLogicalName,
        BlindIndexNormalizerKind normalizer = BlindIndexNormalizerKind.Default,
        string? indexProperty = null)
    {
        ArgumentNullException.ThrowIfNull(propertyBuilder);
        ArgumentException.ThrowIfNullOrWhiteSpace(propertyLogicalName);

        var explicitIndex = string.IsNullOrWhiteSpace(indexProperty) ? null : indexProperty.Trim();
        SetConfiguration(propertyBuilder, new EncryptedPropertyConfiguration(propertyLogicalName.Trim(), IsSearchable: true, normalizer, explicitIndex));
        return propertyBuilder;
    }

    /// <summary>
    /// Marks the property as an encrypted, searchable email field (Email normalizer), the fluent
    /// equivalent of <c>[EncryptedEmail("...")]</c>.
    /// </summary>
    /// <exception cref="ArgumentNullException">The builder is null.</exception>
    /// <exception cref="ArgumentException">The logical name is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">The property already has a fluent encryption configuration.</exception>
    public static PropertyBuilder IsEncryptedEmail(this PropertyBuilder propertyBuilder, string propertyLogicalName, string? indexProperty = null) =>
        propertyBuilder.IsEncryptedSearchable(propertyLogicalName, BlindIndexNormalizerKind.Email, indexProperty);

    /// <summary>
    /// Marks the property as deliberately stored in plaintext, the fluent equivalent of
    /// <c>[Plaintext]</c>. It cannot also be encrypted.
    /// </summary>
    /// <exception cref="ArgumentNullException">The builder is null.</exception>
    /// <exception cref="InvalidOperationException">The property is already configured as encrypted.</exception>
    public static PropertyBuilder IsPlaintext(this PropertyBuilder propertyBuilder)
    {
        ArgumentNullException.ThrowIfNull(propertyBuilder);

        if (propertyBuilder.Metadata.FindAnnotation(EncryptedModelMetadata.FluentPropertyAnnotationName) is not null)
        {
            throw new InvalidOperationException(
                $"Property '{Describe(propertyBuilder)}' is configured as encrypted; it cannot also be plaintext.");
        }

        propertyBuilder.Metadata.SetAnnotation(EncryptedModelMetadata.FluentPlaintextAnnotationName, true);
        return propertyBuilder;
    }

    private static void SetConfiguration(PropertyBuilder propertyBuilder, EncryptedPropertyConfiguration configuration)
    {
        if (propertyBuilder.Metadata.FindAnnotation(EncryptedModelMetadata.FluentPropertyAnnotationName) is not null)
        {
            throw new InvalidOperationException(
                $"Property '{Describe(propertyBuilder)}' already has a Proteos fluent encryption configuration; configure it exactly once.");
        }

        if (propertyBuilder.Metadata.FindAnnotation(EncryptedModelMetadata.FluentPlaintextAnnotationName) is not null)
        {
            throw new InvalidOperationException(
                $"Property '{Describe(propertyBuilder)}' is marked plaintext; it cannot also be encrypted.");
        }

        propertyBuilder.Metadata.SetAnnotation(EncryptedModelMetadata.FluentPropertyAnnotationName, configuration);
    }

    private static string Describe(PropertyBuilder propertyBuilder) =>
        $"{propertyBuilder.Metadata.DeclaringType.ClrType.Name}.{propertyBuilder.Metadata.Name}";
}
