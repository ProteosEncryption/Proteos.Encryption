namespace Proteos.Encryption.Core;

/// <summary>
/// One versioned root key for a rotating <see cref="LocalDevelopmentKeyProvider"/>: the rotation
/// version (1, 2, 3, …) and its development root key. Development-only — the root key is copied on
/// construction and never exposed. Versions are how key rotation is expressed: old versions stay in
/// the provider so data written under them remains decryptable, while new data uses the current one.
/// </summary>
public sealed class LocalDevelopmentKeyVersion
{
    private readonly byte[] _rootKey;

    /// <summary>Creates a versioned root key. The key is copied.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The version is 0 (versions start at 1).</exception>
    /// <exception cref="ArgumentException">The root key is shorter than <see cref="LocalDevelopmentKeyProvider.RootKeyMinLength"/>.</exception>
    public LocalDevelopmentKeyVersion(ushort version, ReadOnlySpan<byte> rootKey)
    {
        if (version == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(version), version, "Key version must be 1 or greater.");
        }

        if (rootKey.Length < LocalDevelopmentKeyProvider.RootKeyMinLength)
        {
            throw new ArgumentException(
                $"Development root key must be at least {LocalDevelopmentKeyProvider.RootKeyMinLength} bytes.",
                nameof(rootKey));
        }

        Version = version;
        _rootKey = rootKey.ToArray();
    }

    /// <summary>The rotation version this root key is registered under.</summary>
    public ushort Version { get; }

    internal byte[] RootKey => _rootKey;
}
