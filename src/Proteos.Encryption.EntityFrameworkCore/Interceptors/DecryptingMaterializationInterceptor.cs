using System.Collections.Concurrent;
using System.Reflection;
using System.Text;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Decrypts encrypted properties when an entity is materialized from the database. It runs only
/// during materialization (a query) — never for entities created, added or attached by the
/// application — so it never re-processes an instance, and no plaintext heuristic is needed.
/// Decryption happens before the change-tracking snapshot is taken, so the decrypted values become
/// the entity's original values and a freshly loaded entity is not seen as modified.
/// </summary>
internal sealed class DecryptingMaterializationInterceptor : IMaterializationInterceptor
{
    private readonly ITenantResolver _tenantResolver;
    private readonly AesGcmValueEncryptionService _encryptionService;
    private readonly IServiceProvider _serviceProvider;
    private readonly ConcurrentDictionary<(Type Type, string Property), PropertyInfo> _properties = new();

    public DecryptingMaterializationInterceptor(
        ITenantResolver tenantResolver,
        AesGcmValueEncryptionService encryptionService,
        IServiceProvider serviceProvider)
    {
        _tenantResolver = tenantResolver ?? throw new ArgumentNullException(nameof(tenantResolver));
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    }

    public object InitializedInstance(MaterializationInterceptionData materializationData, object instance)
    {
        var metadata = EncryptedModelMetadata.Find(materializationData.EntityType);
        if (metadata is null || !metadata.HasEncryptedProperties)
        {
            return instance;
        }

        var clrType = materializationData.EntityType.ClrType;

        var tenant = _tenantResolver.Resolve(_serviceProvider);

        foreach (var descriptor in metadata.Properties)
        {
            DecryptProperty(instance, clrType, descriptor, tenant);
        }

        return instance;
    }

    private void DecryptProperty(object instance, Type clrType, EncryptedPropertyDescriptor descriptor, TenantId tenant)
    {
        var property = GetProperty(clrType, descriptor.PropertyName);
        var current = property.GetValue(instance);
        if (current is null)
        {
            return; // null -> null
        }

        var isStringProperty = descriptor.PropertyType == typeof(string);
        var envelope = isStringProperty ? DecodeBase64(clrType, descriptor, (string)current) : (byte[])current;

        var encryptionContext = new EncryptionContext(tenant, descriptor.Scope);
        var plaintext = _encryptionService.DecryptFromBytes(envelope, encryptionContext);

        property.SetValue(instance, isStringProperty ? Encoding.UTF8.GetString(plaintext) : plaintext);
    }

    private static byte[] DecodeBase64(Type clrType, EncryptedPropertyDescriptor descriptor, string value)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new ProteosEncryptionException(
                $"Could not decrypt '{clrType.Name}.{descriptor.PropertyName}': the stored value is not a valid encrypted envelope.",
                exception);
        }
    }

    private PropertyInfo GetProperty(Type type, string name) =>
        _properties.GetOrAdd(
            (type, name),
            key => key.Type.GetProperty(key.Property, BindingFlags.Public | BindingFlags.Instance)!);
}
