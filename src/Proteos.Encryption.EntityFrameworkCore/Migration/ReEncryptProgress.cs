namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Cumulative progress of a re-encryption run across batches: running totals of values re-encrypted,
/// skipped and failed, the token to resume from and whether the run is complete. Immutable — each
/// batch yields a new value via <see cref="AfterBatch"/>. The foundation tracks progress only; it
/// does not execute anything. A worker would loop:
/// <code>
/// var progress = ReEncryptProgress.NotStarted;
/// do
/// {
///     ReEncryptBatchResult batch = RunBatch(options, progress.Resume); // worker-supplied
///     progress = progress.AfterBatch(batch);
/// }
/// while (!progress.IsComplete);
/// </code>
/// </summary>
public sealed class ReEncryptProgress
{
    /// <summary>The progress before any batch has run.</summary>
    public static ReEncryptProgress NotStarted { get; } = new(0, 0, 0, ReEncryptResumeToken.Beginning, isComplete: false);

    /// <summary>Creates a progress snapshot.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A count is negative.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="resume"/> is null.</exception>
    public ReEncryptProgress(long reEncrypted, long skipped, long failed, ReEncryptResumeToken resume, bool isComplete)
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
        Resume = resume ?? throw new ArgumentNullException(nameof(resume));
        IsComplete = isComplete;
    }

    /// <summary>Total values re-encrypted to the current key so far.</summary>
    public long ReEncrypted { get; }

    /// <summary>Total values already on the current key (skipped) so far.</summary>
    public long Skipped { get; }

    /// <summary>Total values that failed so far.</summary>
    public long Failed { get; }

    /// <summary>Total values processed so far.</summary>
    public long Processed => ReEncrypted + Skipped + Failed;

    /// <summary>The token to resume the run from.</summary>
    public ReEncryptResumeToken Resume { get; }

    /// <summary>True when the run has processed its last batch.</summary>
    public bool IsComplete { get; }

    /// <summary>Returns a new progress with the batch's counts added and its resume token adopted.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="batch"/> is null.</exception>
    public ReEncryptProgress AfterBatch(ReEncryptBatchResult batch)
    {
        ArgumentNullException.ThrowIfNull(batch);

        return new ReEncryptProgress(
            ReEncrypted + batch.ReEncrypted,
            Skipped + batch.Skipped,
            Failed + batch.Failed,
            batch.NextResume,
            isComplete: !batch.HasMore);
    }
}
