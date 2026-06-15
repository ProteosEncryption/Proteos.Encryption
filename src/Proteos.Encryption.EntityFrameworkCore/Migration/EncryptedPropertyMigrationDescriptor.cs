using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// One property of an entity that is stored under an older key version and should be migrated to the
/// current one: the encrypted property and the key ids that were detected. It is the result of
/// header inspection — no plaintext is read to produce it.
/// </summary>
public sealed record EncryptedPropertyMigrationDescriptor(
    EncryptedPropertyDescriptor Property,
    KeyId StoredKeyId,
    KeyId CurrentKeyId)
{
    /// <summary>True when the stored value is under a different key id than the current one.</summary>
    public bool NeedsReEncryption => !StoredKeyId.Equals(CurrentKeyId);
}
