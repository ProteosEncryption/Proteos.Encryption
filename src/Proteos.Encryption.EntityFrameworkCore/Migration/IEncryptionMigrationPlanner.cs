using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Detects, by inspecting envelope headers only, which encrypted values are stored under an older
/// key version and therefore need re-encryption. It reads no plaintext and performs no decryption,
/// so it is cheap enough to scan with. A later worker uses it to build per-entity migration plans.
/// </summary>
public interface IEncryptionMigrationPlanner
{
    /// <summary>Reads the key id stamped on a stored value, or null when the value is null.</summary>
    /// <exception cref="ArgumentNullException">The property type is null.</exception>
    /// <exception cref="ProteosEncryptionException">The stored value is not a valid envelope.</exception>
    KeyId? ReadStoredKeyId(Type propertyType, object? storedValue);

    /// <summary>True when the stored value exists and is under a different key id than the current one.</summary>
    /// <exception cref="ArgumentNullException">The property type or current key id is null.</exception>
    /// <exception cref="ProteosEncryptionException">The stored value is not a valid envelope.</exception>
    bool NeedsReEncryption(Type propertyType, object? storedValue, KeyId currentKeyId);

    /// <summary>
    /// Builds the migration plan for an entity from its encrypted metadata and the stored values of
    /// its encrypted properties (keyed by property name; a missing or null value is skipped).
    /// </summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ProteosEncryptionException">A stored value is not a valid envelope.</exception>
    EncryptedEntityMigrationPlan CreatePlan(EncryptedEntityMetadata metadata, IReadOnlyDictionary<string, object?> storedValues, TenantId tenant);
}
