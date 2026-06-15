using Microsoft.CodeAnalysis;

namespace Proteos.Encryption.Analyzers;

/// <summary>
/// The symbols the analyzer resolves once per compilation: the <c>EncryptedAttribute</c> base type
/// (the attribute marker for encrypted properties), the fluent <c>ProteosEncryptionPropertyBuilderExtensions</c>
/// type (the fluent markers <c>IsEncrypted</c>/<c>IsEncryptedSearchable</c>/<c>IsEncryptedEmail</c>) and
/// <c>System.Linq.Queryable</c> (to scope the rules to database-translated LINQ). This is the single
/// point that decides "is this property encrypted?", whether configured by attribute or fluently.
/// </summary>
internal sealed class ProteosKnownSymbols
{
    private const string EncryptedAttributeMetadataName = "Proteos.Encryption.EntityFrameworkCore.EncryptedAttribute";
    private const string FluentExtensionsMetadataName = "Microsoft.EntityFrameworkCore.ProteosEncryptionPropertyBuilderExtensions";
    private const string QueryableMetadataName = "System.Linq.Queryable";

    /// <summary>The fluent methods that configure a property as encrypted. <c>IsPlaintext</c> is excluded.</summary>
    private static readonly string[] FluentEncryptionMethodNames = { "IsEncrypted", "IsEncryptedSearchable", "IsEncryptedEmail" };

    private readonly INamedTypeSymbol _encryptedAttribute;
    private readonly INamedTypeSymbol? _fluentExtensions;

    private ProteosKnownSymbols(INamedTypeSymbol encryptedAttribute, INamedTypeSymbol? fluentExtensions, INamedTypeSymbol? queryable)
    {
        _encryptedAttribute = encryptedAttribute;
        _fluentExtensions = fluentExtensions;
        Queryable = queryable;
    }

    /// <summary>The <c>System.Linq.Queryable</c> type, or null if LINQ is not referenced.</summary>
    public INamedTypeSymbol? Queryable { get; }

    /// <summary>
    /// Resolves the known symbols, or returns null when the compilation does not reference Proteos
    /// encryption (no <c>EncryptedAttribute</c>), in which case there is nothing to analyze.
    /// </summary>
    public static ProteosKnownSymbols? TryCreate(Compilation compilation)
    {
        var encryptedAttribute = compilation.GetTypeByMetadataName(EncryptedAttributeMetadataName);
        if (encryptedAttribute is null)
        {
            return null;
        }

        return new ProteosKnownSymbols(
            encryptedAttribute,
            compilation.GetTypeByMetadataName(FluentExtensionsMetadataName),
            compilation.GetTypeByMetadataName(QueryableMetadataName));
    }

    /// <summary>True when the property carries an attribute that is or derives from <c>EncryptedAttribute</c>.</summary>
    public bool IsEncryptedProperty(IPropertySymbol property)
    {
        foreach (var attribute in property.GetAttributes())
        {
            if (InheritsFromEncryptedAttribute(attribute.AttributeClass))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when the method is one of the fluent encryption configuration methods
    /// (<c>IsEncrypted</c>/<c>IsEncryptedSearchable</c>/<c>IsEncryptedEmail</c>) on the Proteos property
    /// builder extensions. Returns false when fluent configuration is not referenced by the compilation.
    /// </summary>
    public bool IsFluentEncryptionMethod(IMethodSymbol method)
    {
        var containingType = (method.ReducedFrom ?? method).ContainingType;
        if (_fluentExtensions is null || !SymbolEqualityComparer.Default.Equals(containingType, _fluentExtensions))
        {
            return false;
        }

        foreach (var name in FluentEncryptionMethodNames)
        {
            if (method.Name == name)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True when the method is declared on <c>System.Linq.Queryable</c> (database-translated LINQ).</summary>
    public bool IsQueryableMethod(IMethodSymbol method) =>
        Queryable is not null && SymbolEqualityComparer.Default.Equals(method.ContainingType, Queryable);

    private bool InheritsFromEncryptedAttribute(INamedTypeSymbol? attributeClass)
    {
        for (var current = attributeClass; current is not null; current = current.BaseType)
        {
            if (SymbolEqualityComparer.Default.Equals(current, _encryptedAttribute))
            {
                return true;
            }
        }

        return false;
    }
}
