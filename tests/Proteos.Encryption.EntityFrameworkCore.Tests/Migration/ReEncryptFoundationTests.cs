using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Migration;

public sealed class ReEncryptFoundationTests
{
    [Fact]
    public void ResumeToken_Beginning_HasNoCursor()
    {
        Assert.True(ReEncryptResumeToken.Beginning.IsBeginning);
        Assert.Null(ReEncryptResumeToken.Beginning.Cursor);
    }

    [Fact]
    public void ResumeToken_FromCursor_CarriesTheCursor()
    {
        var token = ReEncryptResumeToken.FromCursor("pk:42");

        Assert.False(token.IsBeginning);
        Assert.Equal("pk:42", token.Cursor);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ResumeToken_FromCursor_RejectsEmptyCursor(string? cursor)
    {
        // ThrowIfNullOrWhiteSpace throws ArgumentNullException for null and ArgumentException otherwise;
        // both derive from ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() => ReEncryptResumeToken.FromCursor(cursor!));
    }

    [Fact]
    public void ResumeToken_Equality_IsByCursor()
    {
        Assert.Equal(ReEncryptResumeToken.FromCursor("pk:1"), ReEncryptResumeToken.FromCursor("pk:1"));
        Assert.NotEqual(ReEncryptResumeToken.FromCursor("pk:1"), ReEncryptResumeToken.FromCursor("pk:2"));
        Assert.Equal(ReEncryptResumeToken.Beginning, ReEncryptResumeToken.Beginning);
        Assert.NotEqual(ReEncryptResumeToken.Beginning, ReEncryptResumeToken.FromCursor("pk:1"));
    }

    [Fact]
    public void BatchOptions_Default_Is500()
    {
        Assert.Equal(500, ReEncryptBatchOptions.DefaultBatchSize);
        Assert.Equal(500, ReEncryptBatchOptions.Default.BatchSize);
        Assert.Equal(500, new ReEncryptBatchOptions().BatchSize);
    }

    [Fact]
    public void BatchOptions_AcceptsPositiveSize()
    {
        Assert.Equal(250, new ReEncryptBatchOptions(250).BatchSize);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void BatchOptions_RejectsNonPositiveSize(int batchSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReEncryptBatchOptions(batchSize));
    }

    [Fact]
    public void BatchResult_Processed_IsTheSumOfCounts()
    {
        var result = new ReEncryptBatchResult(reEncrypted: 7, skipped: 2, failed: 1, ReEncryptResumeToken.FromCursor("pk:10"), hasMore: true);

        Assert.Equal(10, result.Processed);
        Assert.True(result.HasMore);
        Assert.Equal("pk:10", result.NextResume.Cursor);
    }

    [Fact]
    public void BatchResult_RejectsNegativeCountsAndNullResume()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReEncryptBatchResult(-1, 0, 0, ReEncryptResumeToken.Beginning, false));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReEncryptBatchResult(0, -1, 0, ReEncryptResumeToken.Beginning, false));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ReEncryptBatchResult(0, 0, -1, ReEncryptResumeToken.Beginning, false));
        Assert.Throws<ArgumentNullException>(() => new ReEncryptBatchResult(0, 0, 0, null!, false));
    }

    [Fact]
    public void Progress_NotStarted_IsZeroAtTheBeginning()
    {
        var progress = ReEncryptProgress.NotStarted;

        Assert.Equal(0, progress.Processed);
        Assert.False(progress.IsComplete);
        Assert.True(progress.Resume.IsBeginning);
    }

    [Fact]
    public void Progress_AfterBatch_AccumulatesCountsAndAdoptsResume()
    {
        var batch = new ReEncryptBatchResult(reEncrypted: 5, skipped: 3, failed: 1, ReEncryptResumeToken.FromCursor("pk:9"), hasMore: true);

        var progress = ReEncryptProgress.NotStarted.AfterBatch(batch);

        Assert.Equal(5, progress.ReEncrypted);
        Assert.Equal(3, progress.Skipped);
        Assert.Equal(1, progress.Failed);
        Assert.Equal(9, progress.Processed);
        Assert.False(progress.IsComplete);
        Assert.Equal("pk:9", progress.Resume.Cursor);
    }

    [Fact]
    public void Progress_AfterFinalBatch_IsComplete_AndAccumulatesAcrossBatches()
    {
        var first = new ReEncryptBatchResult(10, 0, 0, ReEncryptResumeToken.FromCursor("pk:10"), hasMore: true);
        var last = new ReEncryptBatchResult(4, 1, 0, ReEncryptResumeToken.FromCursor("pk:15"), hasMore: false);

        var progress = ReEncryptProgress.NotStarted.AfterBatch(first).AfterBatch(last);

        Assert.Equal(14, progress.ReEncrypted);
        Assert.Equal(1, progress.Skipped);
        Assert.Equal(15, progress.Processed);
        Assert.True(progress.IsComplete);
        Assert.Equal("pk:15", progress.Resume.Cursor);
    }

    [Fact]
    public void Progress_AfterBatch_RejectsNullBatch()
    {
        Assert.Throws<ArgumentNullException>(() => ReEncryptProgress.NotStarted.AfterBatch(null!));
    }
}
