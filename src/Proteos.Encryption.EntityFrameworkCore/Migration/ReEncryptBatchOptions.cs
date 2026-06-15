namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Configuration for one re-encryption batch: how many stored values a future worker should process
/// per batch. A pure value object — it performs no work and touches no database; it only carries and
/// validates the batch size.
/// </summary>
public sealed class ReEncryptBatchOptions
{
    /// <summary>The batch size used when none is specified.</summary>
    public const int DefaultBatchSize = 500;

    /// <summary>Creates batch options with a positive batch size (defaults to <see cref="DefaultBatchSize"/>).</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="batchSize"/> is not positive.</exception>
    public ReEncryptBatchOptions(int batchSize = DefaultBatchSize)
    {
        if (batchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(batchSize), batchSize, "Batch size must be a positive number.");
        }

        BatchSize = batchSize;
    }

    /// <summary>The maximum number of stored values to process in one batch.</summary>
    public int BatchSize { get; }

    /// <summary>Options with the default batch size.</summary>
    public static ReEncryptBatchOptions Default { get; } = new();
}
