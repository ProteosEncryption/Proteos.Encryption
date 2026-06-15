namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// The outcome of a single re-encryption batch: how many stored values were re-encrypted, how many
/// were already on the current key (skipped) and how many failed, plus the token to resume from and
/// whether more batches remain. A pure value object describing a batch; a future worker produces it,
/// the foundation only defines its shape.
/// </summary>
public sealed class ReEncryptBatchResult
{
    /// <summary>Creates a batch result.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A count is negative.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="nextResume"/> is null.</exception>
    public ReEncryptBatchResult(int reEncrypted, int skipped, int failed, ReEncryptResumeToken nextResume, bool hasMore)
    {
        if (reEncrypted < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(reEncrypted), reEncrypted, "Count cannot be negative.");
        }

        if (skipped < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(skipped), skipped, "Count cannot be negative.");
        }

        if (failed < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(failed), failed, "Count cannot be negative.");
        }

        ReEncrypted = reEncrypted;
        Skipped = skipped;
        Failed = failed;
        NextResume = nextResume ?? throw new ArgumentNullException(nameof(nextResume));
        HasMore = hasMore;
    }

    /// <summary>Values re-encrypted to the current key in this batch.</summary>
    public int ReEncrypted { get; }

    /// <summary>Values already on the current key, left unchanged in this batch.</summary>
    public int Skipped { get; }

    /// <summary>Values that could not be processed in this batch.</summary>
    public int Failed { get; }

    /// <summary>Total values processed in this batch.</summary>
    public int Processed => ReEncrypted + Skipped + Failed;

    /// <summary>The token a subsequent batch should resume from.</summary>
    public ReEncryptResumeToken NextResume { get; }

    /// <summary>True when more batches remain after this one.</summary>
    public bool HasMore { get; }
}
