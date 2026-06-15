using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Maps a <see cref="BlindIndexNormalizerKind"/> to the concrete crypto-core normalizer. This is
/// the stable bridge the later EF Core integration will use; it performs no EF runtime work.
/// </summary>
public static class BlindIndexNormalizerResolver
{
    public static IBlindIndexNormalizer Resolve(BlindIndexNormalizerKind kind) => kind switch
    {
        BlindIndexNormalizerKind.Default => DefaultBlindIndexNormalizer.Instance,
        BlindIndexNormalizerKind.Email => EmailBlindIndexNormalizer.Instance,
        _ => throw new EncryptedEntityMetadataException($"Unsupported blind index normalizer kind '{kind}'."),
    };
}
