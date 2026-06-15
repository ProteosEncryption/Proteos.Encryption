using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Header-inspecting implementation of <see cref="IEncryptionMigrationPlanner"/>. It parses the
/// stored envelope (Base64 for a string property, raw bytes for a <c>byte[]</c> property), reads
/// <c>Header.KeyId</c> and compares it with the tenant's current key id — no decryption, no plaintext.
/// </summary>
public sealed class EncryptionMigrationPlanner : IEncryptionMigrationPlanner
{
    private readonly ICiphertextEnvelopeCodec _codec;
    private readonly IKeyMaterialProvider _keyProvider;

    public EncryptionMigrationPlanner(ICiphertextEnvelopeCodec codec, IKeyMaterialProvider keyProvider)
    {
        _codec = codec ?? throw new ArgumentNullException(nameof(codec));
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
    }

    /// <inheritdoc />
    public KeyId? ReadStoredKeyId(Type propertyType, object? storedValue)
    {
        ArgumentNullException.ThrowIfNull(propertyType);

        if (storedValue is null)
        {
            return null;
        }

        return _codec.Parse(ToEnvelopeBytes(propertyType, storedValue)).Header.KeyId;
    }

    /// <inheritdoc />
    public bool NeedsReEncryption(Type propertyType, object? storedValue, KeyId currentKeyId)
    {
        ArgumentNullException.ThrowIfNull(currentKeyId);

        var storedKeyId = ReadStoredKeyId(propertyType, storedValue);
        return storedKeyId is not null && !storedKeyId.Equals(currentKeyId);
    }

    /// <inheritdoc />
    public EncryptedEntityMigrationPlan CreatePlan(EncryptedEntityMetadata metadata, IReadOnlyDictionary<string, object?> storedValues, TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(storedValues);
        ArgumentNullException.ThrowIfNull(tenant);

        var currentKeyId = _keyProvider.GetCurrentKeyId(tenant);

        var toMigrate = new List<EncryptedPropertyMigrationDescriptor>();
        foreach (var descriptor in metadata.Properties)
        {
            var storedKeyId = ReadStoredKeyId(descriptor.PropertyType, storedValues.GetValueOrDefault(descriptor.PropertyName));
            if (storedKeyId is not null && !storedKeyId.Equals(currentKeyId))
            {
                toMigrate.Add(new EncryptedPropertyMigrationDescriptor(descriptor, storedKeyId, currentKeyId));
            }
        }

        return new EncryptedEntityMigrationPlan(metadata.EntityType, toMigrate);
    }

    private static byte[] ToEnvelopeBytes(Type propertyType, object storedValue)
    {
        if (propertyType == typeof(string))
        {
            if (storedValue is not string text)
            {
                throw new ArgumentException($"A string property's stored value must be a string, but was '{storedValue.GetType().Name}'.", nameof(storedValue));
            }

            return DecodeBase64(text);
        }

        if (propertyType == typeof(byte[]))
        {
            if (storedValue is not byte[] bytes)
            {
                throw new ArgumentException($"A byte[] property's stored value must be a byte[], but was '{storedValue.GetType().Name}'.", nameof(storedValue));
            }

            return bytes;
        }

        throw new ArgumentException($"Unsupported encrypted property type '{propertyType.Name}'. Supported types are string and byte[].", nameof(propertyType));
    }

    private static byte[] DecodeBase64(string value)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new ProteosEncryptionException("The stored value is not a valid encrypted envelope (invalid Base64).", exception);
        }
    }
}
