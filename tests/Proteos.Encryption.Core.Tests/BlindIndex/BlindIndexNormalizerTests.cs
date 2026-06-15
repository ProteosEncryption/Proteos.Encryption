using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.BlindIndex;

public sealed class DefaultBlindIndexNormalizerTests
{
    private static readonly IBlindIndexNormalizer Normalizer = DefaultBlindIndexNormalizer.Instance;

    [Fact]
    public void TrimsSurroundingWhitespace()
    {
        Assert.Equal("value", Normalizer.Normalize("  value  "));
    }

    [Fact]
    public void IsCaseSensitive()
    {
        Assert.Equal("Value", Normalizer.Normalize("Value"));
    }

    [Fact]
    public void AppliesUnicodeNfc()
    {
        // "e" + combining acute accent (U+0301) normalizes to the composed "é" (U+00E9).
        var decomposed = "e" + (char)0x0301;

        Assert.Equal(((char)0x00e9).ToString(), Normalizer.Normalize(decomposed));
    }

    [Fact]
    public void RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => Normalizer.Normalize(null!));
    }
}

public sealed class EmailBlindIndexNormalizerTests
{
    private static readonly IBlindIndexNormalizer Normalizer = EmailBlindIndexNormalizer.Instance;

    [Fact]
    public void TrimsAndLowercasesInvariantly()
    {
        Assert.Equal("max@example.com", Normalizer.Normalize("  Max@Example.COM  "));
    }

    [Fact]
    public void LowercasesAscii()
    {
        Assert.Equal("abc", Normalizer.Normalize("ABC"));
    }

    [Fact]
    public void RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => Normalizer.Normalize(null!));
    }
}
