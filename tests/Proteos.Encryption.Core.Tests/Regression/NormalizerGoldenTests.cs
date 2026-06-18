using Proteos.Encryption.Core;
using Xunit;

namespace Proteos.Encryption.Core.Tests.Regression;

/// <summary>
/// Golden tests that pin the EXACT normalized output of the blind-index normalizers. Normalization is
/// part of the blind-index data contract: a silent change — for example NFC to NFKC, or a different
/// operation order — would leave existing blind indexes unmatchable without any decryption error to
/// signal it. These tests freeze the documented behaviour: the Default normalizer trims then applies
/// NFC and is case-sensitive; the Email normalizer trims, lower-cases with the invariant culture, then
/// applies NFC. NFC, never NFKC. Non-ASCII inputs are built from explicit code points so the
/// decomposed-vs-composed distinction is unambiguous in source.
/// </summary>
public sealed class DefaultNormalizerGoldenTests
{
    private static readonly IBlindIndexNormalizer Normalizer = DefaultBlindIndexNormalizer.Instance;

    [Theory]
    [InlineData("value", "value")]          // ASCII passes through unchanged
    [InlineData("  value  ", "value")]      // surrounding whitespace trimmed
    [InlineData("a b c", "a b c")]          // embedded whitespace preserved
    [InlineData("  a b  ", "a b")]          // only the outer whitespace is trimmed
    [InlineData("Value", "Value")]          // case preserved (case-sensitive)
    [InlineData("", "")]                    // empty stays empty
    [InlineData("   ", "")]                 // whitespace-only trims to empty
    public void PinsExactNormalizedOutput_AsciiAndWhitespace(string input, string expected)
    {
        Assert.Equal(expected, Normalizer.Normalize(input));
    }

    [Fact]
    public void ComposesNfdInputToNfc()
    {
        // "e" + combining acute (U+0301) must compose to "é" (U+00E9).
        var decomposed = "e" + (char)0x0301;
        Assert.Equal(((char)0x00e9).ToString(), Normalizer.Normalize(decomposed));
    }

    [Fact]
    public void LeavesAlreadyComposedNfcUnchanged()
    {
        var composed = ((char)0x00e9).ToString();
        Assert.Equal(composed, Normalizer.Normalize(composed));
    }

    [Fact]
    public void LeavesNonLatinScriptUnchanged()
    {
        // Cyrillic "Москва" — already NFC; the Default normalizer is case-sensitive, so it is unchanged.
        var moskva = CodePoints.Of(0x041c, 0x043e, 0x0441, 0x043a, 0x0432, 0x0430);
        Assert.Equal(moskva, Normalizer.Normalize(moskva));
    }

    [Fact]
    public void LeavesEmojiUnchanged()
    {
        var lockEmoji = CodePoints.Of(0x1F512); // U+1F512 LOCK
        Assert.Equal(lockEmoji, Normalizer.Normalize(lockEmoji));
    }

    [Fact]
    public void DoesNotApplyCompatibilityFolding_NfcNotNfkc()
    {
        // NFC must not fold compatibility characters (that is NFKC). The "fi" ligature (U+FB01) and a
        // full-width letter (U+FF21) must survive unchanged; under NFKC they would become "fi" and "A".
        var ligature = CodePoints.Of(0xFB01);
        var fullWidthA = CodePoints.Of(0xFF21);
        Assert.Equal(ligature, Normalizer.Normalize(ligature));
        Assert.Equal(fullWidthA, Normalizer.Normalize(fullWidthA));
    }
}

/// <summary>
/// Golden tests pinning the exact normalized output of the Email normalizer
/// (trim, then invariant lower-case, then NFC).
/// </summary>
public sealed class EmailNormalizerGoldenTests
{
    private static readonly IBlindIndexNormalizer Normalizer = EmailBlindIndexNormalizer.Instance;

    [Theory]
    [InlineData("  Max@Example.COM  ", "max@example.com")]       // trim + invariant lower-case (local and domain)
    [InlineData("ABC", "abc")]                                   // ASCII lower-cased
    [InlineData("Max+News@Example.com", "max+news@example.com")] // plus-address preserved, lower-cased
    [InlineData("", "")]                                         // empty stays empty
    [InlineData("   ", "")]                                      // whitespace-only trims to empty
    public void PinsExactNormalizedOutput_AsciiAndWhitespace(string input, string expected)
    {
        Assert.Equal(expected, Normalizer.Normalize(input));
    }

    [Fact]
    public void LowerCasesThenComposesNfc()
    {
        // Trim -> invariant lower-case -> NFC: "E" + combining acute (U+0301) -> "é" (U+00E9).
        var decomposed = "E" + (char)0x0301;
        Assert.Equal(((char)0x00e9).ToString(), Normalizer.Normalize(decomposed));
    }

    [Fact]
    public void LowerCasesNonLatinInvariantly()
    {
        // Cyrillic "ПОЧТА" -> "почта" via the invariant culture.
        var upper = CodePoints.Of(0x041f, 0x041e, 0x0427, 0x0422, 0x0410) + "@Example.COM";
        var expected = CodePoints.Of(0x043f, 0x043e, 0x0447, 0x0442, 0x0430) + "@example.com";
        Assert.Equal(expected, Normalizer.Normalize(upper));
    }

    [Fact]
    public void DoesNotApplyCompatibilityFolding_NfcNotNfkc()
    {
        // The ligature (U+FB01) has no case mapping; NFC keeps it (NFKC would yield "fi").
        var ligature = CodePoints.Of(0xFB01);
        Assert.Equal(ligature, Normalizer.Normalize(ligature));
    }
}

/// <summary>Builds strings from explicit Unicode code points, so test vectors are unambiguous in source.</summary>
internal static class CodePoints
{
    public static string Of(params int[] codePoints) => string.Concat(codePoints.Select(char.ConvertFromUtf32));
}
