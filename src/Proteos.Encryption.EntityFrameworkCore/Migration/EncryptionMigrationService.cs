using System.Security.Cryptography;
using System.Text;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Re-encrypts stored values to the current key by going through plaintext: it decrypts under the key
/// id stamped on the envelope (which may be an old version) and re-encrypts under the current key,
/// then, for a searchable property, recomputes the blind index. The plaintext is zeroed as soon as
/// both steps are done. It reuses the same encryption and blind index services the interceptors use,
/// so a migrated value is indistinguishable from a freshly written one.
/// </summary>
internal sealed class EncryptionMigrationService : IEncryptionMigrationService
{
    private readonly AesGcmValueEncryptionService _encryptionService;
    private readonly IBlindIndexProvider _blindIndexProvider;

    public EncryptionMigrationService(AesGcmValueEncryptionService encryptionService, IBlindIndexProvider blindIndexProvider)
    {
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        _blindIndexProvider = blindIndexProvider ?? throw new ArgumentNullException(nameof(blindIndexProvider));
    }

    /// <inheritdoc />
    public MigratedEncryptedProperty ReEncrypt(EncryptedPropertyDescriptor descriptor, object storedValue, TenantId tenant)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(storedValue);
        ArgumentNullException.ThrowIfNull(tenant);

        var context = new EncryptionContext(tenant, descriptor.Scope);
        var isString = descriptor.PropertyType == typeof(string);
        var envelopeBytes = isString ? DecodeBase64((string)storedValue) : (byte[])storedValue;

        // Decrypt under the stored (possibly old) key id, then re-encrypt under the current one.
        var plaintext = _encryptionService.DecryptFromBytes(envelopeBytes, context);
        try
        {
            var newEnvelope = _encryptionService.EncryptToBytes(plaintext, context);
            object newValue = isString ? Convert.ToBase64String(newEnvelope) : newEnvelope;

            var newBlindIndex = descriptor.IsSearchable ? ComputeBlindIndex(plaintext, descriptor, context) : null;

            return new MigratedEncryptedProperty(descriptor.PropertyName, newValue, descriptor.IndexPropertyName, newBlindIndex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private byte[] ComputeBlindIndex(byte[] plaintext, EncryptedPropertyDescriptor descriptor, EncryptionContext context)
    {
        // Searchable is string-only (enforced by the scanner): index the normalized plaintext under the current key.
        var normalizer = BlindIndexNormalizerResolver.Resolve(descriptor.NormalizerKind!.Value);
        var normalized = normalizer.Normalize(Encoding.UTF8.GetString(plaintext));
        return _blindIndexProvider.Compute(Encoding.UTF8.GetBytes(normalized), BlindIndexDescriptor.ExactMatch, context).ToArray();
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
