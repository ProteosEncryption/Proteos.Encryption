using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Re-encrypts a single stored encrypted value to the current key, and — for a searchable property —
/// recomputes its blind index with the current index key. Because a blind index can only be derived
/// from plaintext, re-encryption is necessarily decrypt + encrypt + reindex, not an in-place header
/// rewrite. It does not touch the database; a worker applies the returned value and index.
/// </summary>
public interface IEncryptionMigrationService
{
    /// <summary>Re-encrypts a stored value (and reindexes if searchable) to the current key.</summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ProteosEncryptionException">The stored value cannot be decrypted (invalid envelope, wrong tenant/scope, or tampered).</exception>
    MigratedEncryptedProperty ReEncrypt(EncryptedPropertyDescriptor descriptor, object storedValue, TenantId tenant);
}
