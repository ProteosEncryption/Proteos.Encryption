using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Maps a <see cref="BlindIndexNormalizerKind"/> to the concrete crypto-core normalizer. Internal
/// helper used by the EF integration; not part of the public API.
/// </summary>
internal static class BlindIndexNormalizerResolver
{
    public static IBlindIndexNormalizer Resolve(BlindIndexNormalizerKind kind) => kind switch
    {
        BlindIndexNormalizerKind.Default => DefaultBlindIndexNormalizer.Instance,
        BlindIndexNormalizerKind.Email => EmailBlindIndexNormalizer.Instance,
        _ => throw new EncryptedEntityMetadataException($"Unsupported blind index normalizer kind '{kind}'."),
    };
}
