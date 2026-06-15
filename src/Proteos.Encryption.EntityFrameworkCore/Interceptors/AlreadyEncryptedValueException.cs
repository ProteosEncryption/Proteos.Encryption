using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Thrown by the save interceptor when a property scheduled for encryption already holds a Proteos
/// ciphertext envelope. Encrypting it again would produce <c>Encrypt(Base64(Encrypt(...)))</c> and
/// silently corrupt the value, so the save is refused rather than quietly "fixed". The usual cause
/// is attaching or updating an entity whose encrypted property was loaded by a context without the
/// Proteos decrypting interceptor (so it still carries ciphertext), or assigning a raw stored value
/// directly. Assign the plaintext value instead.
/// </summary>
public sealed class AlreadyEncryptedValueException : ProteosEncryptionException
{
    public AlreadyEncryptedValueException(Type entityType, string propertyName)
        : base(BuildMessage(entityType, propertyName))
    {
        EntityType = entityType;
        PropertyName = propertyName ?? throw new ArgumentNullException(nameof(propertyName));
    }

    /// <summary>The CLR type of the entity whose property already held ciphertext.</summary>
    public Type EntityType { get; }

    /// <summary>The property that already held a Proteos envelope.</summary>
    public string PropertyName { get; }

    private static string BuildMessage(Type entityType, string propertyName)
    {
        ArgumentNullException.ThrowIfNull(entityType);

        return $"Property '{entityType.Name}.{propertyName}' already contains a Proteos ciphertext envelope. "
            + "Encrypting it again would double-encrypt and corrupt the value, so the save was refused. "
            + "This usually means an entity loaded without the Proteos decrypting interceptor (or a raw stored "
            + "value) was attached for saving — assign the plaintext value instead.";
    }
}
