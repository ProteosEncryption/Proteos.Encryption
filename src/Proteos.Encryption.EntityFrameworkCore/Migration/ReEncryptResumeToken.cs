namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// An opaque marker for resuming a re-encryption run where a previous one stopped. It carries a
/// persistence-defined cursor (for example the last processed primary key) so a future batch worker
/// can continue from it. This is foundation only: the token holds and compares a cursor but the
/// foundation neither interprets nor persists it — that is the worker's responsibility.
/// </summary>
public sealed class ReEncryptResumeToken : IEquatable<ReEncryptResumeToken>
{
    private ReEncryptResumeToken(string? cursor) => Cursor = cursor;

    /// <summary>The token for starting from the beginning, before any value has been processed.</summary>
    public static ReEncryptResumeToken Beginning { get; } = new(null);

    /// <summary>The opaque, worker-defined position, or <see langword="null"/> at the beginning.</summary>
    public string? Cursor { get; }

    /// <summary>True when this token represents the start of a run (no position yet).</summary>
    public bool IsBeginning => Cursor is null;

    /// <summary>Creates a token from a worker-defined, non-empty cursor.</summary>
    /// <exception cref="ArgumentException">The cursor is null or whitespace.</exception>
    public static ReEncryptResumeToken FromCursor(string cursor)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cursor);
        return new ReEncryptResumeToken(cursor);
    }

    /// <inheritdoc />
    public bool Equals(ReEncryptResumeToken? other) =>
        other is not null && string.Equals(Cursor, other.Cursor, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as ReEncryptResumeToken);

    /// <inheritdoc />
    public override int GetHashCode() => Cursor is null ? 0 : StringComparer.Ordinal.GetHashCode(Cursor);

    /// <inheritdoc />
    public override string ToString() => IsBeginning ? "ReEncryptResumeToken(beginning)" : $"ReEncryptResumeToken({Cursor})";
}
