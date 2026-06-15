using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// A structured classification of every string/byte[] property in a model: which are encrypted,
/// searchable, explicitly plaintext, or unclassified. It is derived purely from the finalized EF
/// model (the encryption metadata and plaintext annotations the convention writes), so it needs no
/// DI and no reflection. Use it programmatically (for example to log it or to gate a startup check)
/// or read its <see cref="ToString"/> for a human-readable table.
/// </summary>
public sealed class EncryptionAuditReport
{
    private static readonly IReadOnlySet<string> NoNames = new HashSet<string>();

    public EncryptionAuditReport(IReadOnlyList<EncryptionAuditEntry> entries)
    {
        Entries = entries ?? throw new ArgumentNullException(nameof(entries));
        Unclassified = entries.Where(entry => entry.Classification == EncryptionClassification.Unclassified).ToArray();
    }

    /// <summary>Every audited string/byte[] property, across all entity types.</summary>
    public IReadOnlyList<EncryptionAuditEntry> Entries { get; }

    /// <summary>The unclassified properties — empty unless some property is neither encrypted nor plaintext.</summary>
    public IReadOnlyList<EncryptionAuditEntry> Unclassified { get; }

    /// <summary>Builds the report from a model. Reads only model annotations and property types.</summary>
    /// <exception cref="ArgumentNullException">The model is null.</exception>
    public static EncryptionAuditReport Create(IReadOnlyModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var entries = new List<EncryptionAuditEntry>();
        foreach (var entityType in model.GetEntityTypes())
        {
            var metadata = EncryptedModelMetadata.Find(entityType);
            var plaintext = EncryptedModelMetadata.FindPlaintextProperties(entityType);
            var encrypted = metadata is null
                ? new Dictionary<string, EncryptedPropertyDescriptor>(0)
                : metadata.Properties.ToDictionary(descriptor => descriptor.PropertyName, StringComparer.Ordinal);
            var indexColumns = metadata is null
                ? NoNames
                : metadata.Properties.Where(descriptor => descriptor.IsSearchable).Select(descriptor => descriptor.IndexPropertyName!).ToHashSet(StringComparer.Ordinal);

            foreach (var property in entityType.GetProperties())
            {
                if (!IsAuditable(property.ClrType) || property.IsShadowProperty() || indexColumns.Contains(property.Name))
                {
                    continue;
                }

                entries.Add(new EncryptionAuditEntry(
                    entityType.ClrType,
                    metadata?.EntityLogicalName,
                    property.Name,
                    property.ClrType,
                    Classify(property.Name, encrypted, plaintext)));
            }
        }

        return new EncryptionAuditReport(entries);
    }

    public override string ToString()
    {
        if (Entries.Count == 0)
        {
            return "(no string or byte[] properties)";
        }

        var width = Entries.Max(entry => entry.Path.Length);
        var builder = new StringBuilder();
        foreach (var entry in Entries)
        {
            builder.Append(entry.Path.PadRight(width)).Append("  ").AppendLine(Describe(entry.Classification));
        }

        return builder.ToString().TrimEnd();
    }

    private static EncryptionClassification Classify(string propertyName, IReadOnlyDictionary<string, EncryptedPropertyDescriptor> encrypted, IReadOnlySet<string> plaintext)
    {
        if (encrypted.TryGetValue(propertyName, out var descriptor))
        {
            return descriptor.IsSearchable ? EncryptionClassification.EncryptedSearchable : EncryptionClassification.Encrypted;
        }

        return plaintext.Contains(propertyName) ? EncryptionClassification.Plaintext : EncryptionClassification.Unclassified;
    }

    private static bool IsAuditable(Type clrType) => clrType == typeof(string) || clrType == typeof(byte[]);

    private static string Describe(EncryptionClassification classification) => classification switch
    {
        EncryptionClassification.Encrypted => "encrypted",
        EncryptionClassification.EncryptedSearchable => "encrypted searchable",
        EncryptionClassification.Plaintext => "plaintext",
        EncryptionClassification.Unclassified => "UNCLASSIFIED",
        _ => classification.ToString(),
    };
}
