namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Convenience contract combining <see cref="IValueEncryptor"/> and <see cref="IValueDecryptor"/>
/// for consumers that need both directions. The two focused interfaces remain available for
/// dependencies that should only encrypt or only decrypt.
/// </summary>
public interface IValueEncryptionService : IValueEncryptor, IValueDecryptor
{
}
