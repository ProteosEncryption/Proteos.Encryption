using System.Text;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Thrown by the save interceptor when strict mode is enabled and one or more string/byte[]
/// properties are not classified. All violations are reported together, so a single failure lists
/// every property that still needs a classification.
/// </summary>
public sealed class StrictModeViolationException : ProteosEncryptionException
{
    public StrictModeViolationException(IReadOnlyList<EncryptionAuditEntry> violations)
        : base(BuildMessage(violations))
    {
        Violations = violations ?? throw new ArgumentNullException(nameof(violations));
    }

    /// <summary>The unclassified properties that triggered the failure.</summary>
    public IReadOnlyList<EncryptionAuditEntry> Violations { get; }

    private static string BuildMessage(IReadOnlyList<EncryptionAuditEntry> violations)
    {
        var builder = new StringBuilder(
            "Proteos strict mode: the following string/byte[] properties are not classified. Mark each one "
            + "[Encrypted] / [EncryptedSearchable] / [EncryptedEmail] / [Plaintext] (or the fluent equivalent):");

        foreach (var violation in violations)
        {
            builder.Append("\n  ").Append(violation.Path);
        }

        return builder.ToString();
    }
}
