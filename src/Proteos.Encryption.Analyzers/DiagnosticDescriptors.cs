using Microsoft.CodeAnalysis;

namespace Proteos.Encryption.Analyzers;

/// <summary>
/// The diagnostics the Proteos encryption analyzer can report. IDs are stable (<c>PENC{nnn}</c>) and
/// tracked in <c>AnalyzerReleases.*.md</c>. PENC003 is reserved for a future strict-mode rule and is
/// disabled by default; it is declared here so the ID is allocated and discoverable.
/// </summary>
internal static class DiagnosticDescriptors
{
    private const string Category = "Proteos.Encryption";

    /// <summary>PENC001 — an encrypted property is projected directly in a queryable Select.</summary>
    public static readonly DiagnosticDescriptor EncryptedProjection = new(
        id: "PENC001",
        title: "Encrypted property projected directly",
        messageFormat: "Encrypted property '{0}' is projected directly. This returns ciphertext.",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Projecting an encrypted property in an IQueryable Select runs in the database, where the "
            + "materialization interceptor does not apply, so the stored ciphertext is returned. Materialize the "
            + "full entity (and read the property from it) instead of selecting the encrypted column directly.");

    /// <summary>PENC002 — an encrypted property is compared with == / != in a query.</summary>
    public static readonly DiagnosticDescriptor EncryptedEqualityFilter = new(
        id: "PENC002",
        title: "Encrypted property compared for equality in a query",
        messageFormat: "Encrypted property '{0}' is compared with '==' in a query. Encrypted columns hold random ciphertext, so this never matches; use .WhereEncryptedEquals(...) for searchable properties.",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "An encrypted column stores a different ciphertext for every write (random nonce), so a database "
            + "equality comparison against a plaintext value never matches. For searchable properties use the "
            + "blind-index query helper .WhereEncryptedEquals(...).");

    /// <summary>PENC003 — reserved for a future strict-mode rule; not reported yet.</summary>
    public static readonly DiagnosticDescriptor StrictModeReserved = new(
        id: "PENC003",
        title: "Reserved for future strict-mode analysis",
        messageFormat: "PENC003 is reserved for future use.",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: false,
        description: "Reserved. A future release will use this ID to flag strict-mode classification problems "
            + "(unclassified string/byte[] properties) at compile time.");
}
