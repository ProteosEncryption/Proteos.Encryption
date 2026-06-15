using System.Security.Cryptography;
using System.Text;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// Computes blind indexes for exact-match search: <c>HMAC-SHA256(indexKey, normalizedValue)</c>,
/// where the index key is derived per tenant and scope with the blind-index purpose, keeping it
/// separate from the encryption key. The result is the full 32-byte HMAC (never truncated).
/// </summary>
/// <remarks>
/// A blind index is deterministic and one-way: equal values produce equal indexes, enabling
/// equality search, but the index cannot be reversed to the plaintext and stores no plaintext.
/// It is not encryption and does not replace it. Because the index is deterministic it leaks
/// equality and frequency by design. HMAC-SHA256 has only negligible (theoretical) collision
/// probability, which is acceptable for exact-match indexing.
/// </remarks>
public sealed class HmacBlindIndexProvider : IBlindIndexProvider
{
    private readonly IKeyMaterialProvider _keyProvider;

    public HmacBlindIndexProvider(IKeyMaterialProvider keyProvider)
    {
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
    }

    /// <summary>
    /// Computes the blind index of the given value bytes, taken as already normalized. Use
    /// <see cref="CreateIndex(string, EncryptionContext, BlindIndexPurpose)"/> for string values
    /// that need normalization.
    /// </summary>
    public BlindIndexValue Compute(ReadOnlySpan<byte> value, BlindIndexDescriptor descriptor, EncryptionContext context)
    {
        EnsureExactMatch(descriptor, context);

        return ComputeWithKeyId(_keyProvider.GetCurrentKeyId(context.Tenant), value, context);
    }

    /// <summary>
    /// Computes the blind index under every key version the provider still knows for the tenant, so a
    /// search can match data written under any version. One index per version; rotation-aware search
    /// builds an OR over them. The version loop is generic — no per-version special cases.
    /// </summary>
    public IReadOnlyCollection<BlindIndexValue> ComputeForAllKnownKeys(ReadOnlySpan<byte> value, BlindIndexDescriptor descriptor, EncryptionContext context)
    {
        EnsureExactMatch(descriptor, context);

        var keyIds = _keyProvider.GetKnownKeyIds(context.Tenant);
        var indexes = new List<BlindIndexValue>(keyIds.Count);
        foreach (var keyId in keyIds)
        {
            indexes.Add(ComputeWithKeyId(keyId, value, context));
        }

        return indexes;
    }

    private BlindIndexValue ComputeWithKeyId(KeyId keyId, ReadOnlySpan<byte> value, EncryptionContext context)
    {
        var indexKey = _keyProvider.DeriveKey(context.Tenant, new KeyDescriptor(keyId, KeyPurpose.BlindIndex, context.Scope));
        try
        {
            var hash = new byte[HMACSHA256.HashSizeInBytes];
            HMACSHA256.HashData(indexKey, value, hash);
            return BlindIndexValue.Create(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(indexKey);
        }
    }

    private static void EnsureExactMatch(BlindIndexDescriptor descriptor, EncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(context);

        if (descriptor.Purpose != BlindIndexPurpose.ExactMatch)
        {
            throw new NotSupportedException($"Blind index purpose {descriptor.Purpose} is not supported.");
        }
    }

    /// <summary>Computes the blind index of a string value using the default normalizer.</summary>
    public BlindIndexValue CreateIndex(string value, EncryptionContext context, BlindIndexPurpose purpose) =>
        CreateIndex(value, context, purpose, DefaultBlindIndexNormalizer.Instance);

    /// <summary>Computes the blind index of a string value using the given normalizer.</summary>
    public BlindIndexValue CreateIndex(string value, EncryptionContext context, BlindIndexPurpose purpose, IBlindIndexNormalizer normalizer)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(normalizer);

        var normalized = normalizer.Normalize(value);
        var bytes = Encoding.UTF8.GetBytes(normalized);
        return Compute(bytes, new BlindIndexDescriptor(purpose), context);
    }
}
