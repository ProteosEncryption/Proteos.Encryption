using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.Core.Tests.Vectors;
using Xunit;

namespace Proteos.Encryption.Core.Tests.KnownAnswerTests;

/// <summary>
/// Known-answer tests for the blind index. With a fixed index key they pin the full
/// normalize → UTF-8 → HMAC-SHA256 → 32-byte chain to fixed hex values. The expected hashes were
/// produced independently (OpenSSL HMAC-SHA256), not by this code, so they verify the implementation
/// against an external reference rather than against itself. They guard the blind-index data contract:
/// the normalizer feeds UTF-8 bytes into HMAC-SHA256 and the full, untruncated 32-byte output is the
/// index.
/// </summary>
public sealed class BlindIndexKnownAnswerTests
{
    // A fixed 32-byte index key (bytes 0x00..0x1f), used directly as the HMAC key by the fake provider.
    private const string IndexKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    private static EncryptionContext Context() =>
        new(new TenantId("tenant"), new EncryptedDataScope(new LogicalName("Customer"), new LogicalName("Email")));

    private static HmacBlindIndexProvider Provider() =>
        new(new FixedKeyMaterialProvider(Hex.FromHex(IndexKeyHex)));

    [Fact]
    public void Default_AsciiValue_MatchesHmacVector()
    {
        // HMAC-SHA256(key, "Hello")
        var index = Provider().CreateIndex("Hello", Context(), BlindIndexPurpose.ExactMatch, DefaultBlindIndexNormalizer.Instance);

        Assert.Equal("0adc968519e7e86e9fde625df7037baeab85ea5001583b93b9f576258bf7b20c", Hex.ToHex(index.Span));
    }

    [Fact]
    public void Email_NormalizesThenMatchesHmacVector()
    {
        // The Email normalizer turns "  Max@Example.COM  " into "max@example.com"; HMAC-SHA256(key, "max@example.com").
        var index = Provider().CreateIndex("  Max@Example.COM  ", Context(), BlindIndexPurpose.ExactMatch, EmailBlindIndexNormalizer.Instance);

        Assert.Equal("4ae5524f9784da27c3e67d2b769c5a17039d4f891f9100611a17d7b064b73299", Hex.ToHex(index.Span));
    }

    [Fact]
    public void Default_UnicodeNfcValue_MatchesHmacVector()
    {
        // "e" + combining acute (U+0301) normalizes (NFC) to "é" (UTF-8 0xC3 0xA9); HMAC-SHA256(key, 0xC3A9).
        var decomposed = "e" + (char)0x0301;

        var index = Provider().CreateIndex(decomposed, Context(), BlindIndexPurpose.ExactMatch, DefaultBlindIndexNormalizer.Instance);

        Assert.Equal("2445a1fe5ea6e3a6a788fcd7694ae2e660a1b57669bd103992c9cea6979eedcd", Hex.ToHex(index.Span));
    }

    /// <summary>An <see cref="IKeyMaterialProvider"/> that returns one fixed key, so the test pins the
    /// HMAC step against a known key independent of the derivation chain.</summary>
    private sealed class FixedKeyMaterialProvider : IKeyMaterialProvider
    {
        private readonly byte[] _key;

        public FixedKeyMaterialProvider(byte[] key) => _key = key;

        public string ProviderId => "fixed-test-key";

        public KeyId GetCurrentKeyId(TenantId tenant) => KeyId.FromBytes(new byte[] { 0x01 });

        // Returns a fresh copy each call: the provider zeroes the key material it receives.
        public byte[] DeriveKey(TenantId tenant, KeyDescriptor descriptor) => (byte[])_key.Clone();
    }
}
