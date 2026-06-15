using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Thrown when an entity's encryption attributes are inconsistent or invalid (for example a
/// missing scope, an unsupported property type, or a blind index that points at a missing or
/// wrongly typed property). Messages name the entity and property but contain no secret data.
/// </summary>
public sealed class EncryptedEntityMetadataException : ProteosEncryptionException
{
    public EncryptedEntityMetadataException(string message)
        : base(message)
    {
    }
}
