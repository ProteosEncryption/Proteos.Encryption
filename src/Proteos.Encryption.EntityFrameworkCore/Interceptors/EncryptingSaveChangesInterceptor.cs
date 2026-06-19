using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Encrypts encrypted properties and fills blind index shadow columns just before changes are
/// saved. It does not decrypt on read — that is the materialization interceptor's job, added
/// later. Encryption happens only for added entities and for the actually-modified properties of
/// modified entities, so calling SaveChanges twice never produces ciphertext of ciphertext.
/// </summary>
internal sealed class EncryptingSaveChangesInterceptor : SaveChangesInterceptor
{
    private readonly ITenantResolver _tenantResolver;
    private readonly AesGcmValueEncryptionService _encryptionService;
    private readonly IBlindIndexProvider _blindIndexProvider;
    private readonly ICiphertextEnvelopeCodec _codec;
    private readonly ProteosEncryptionRuntimeOptions _runtimeOptions;
    private readonly IServiceProvider _serviceProvider;

    public EncryptingSaveChangesInterceptor(
        ITenantResolver tenantResolver,
        AesGcmValueEncryptionService encryptionService,
        IBlindIndexProvider blindIndexProvider,
        ICiphertextEnvelopeCodec codec,
        IServiceProvider serviceProvider)
    {
        _tenantResolver = tenantResolver ?? throw new ArgumentNullException(nameof(tenantResolver));
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        _blindIndexProvider = blindIndexProvider ?? throw new ArgumentNullException(nameof(blindIndexProvider));
        _codec = codec ?? throw new ArgumentNullException(nameof(codec));
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _runtimeOptions = serviceProvider.GetRequiredService<ProteosEncryptionRuntimeOptions>();
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        EncryptPendingChanges(eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        EncryptPendingChanges(eventData.Context);
        return ValueTask.FromResult(result);
    }

    private void EncryptPendingChanges(DbContext? context)
    {
        if (context is null)
        {
            return;
        }

        // Fail loudly if the model convention was never applied, instead of silently writing plaintext.
        EncryptedModelMetadata.EnsureModelApplied(context.Model);

        // Strict mode: at the storage boundary, refuse to write when any string/byte[] property is
        // unclassified. All violations are reported together.
        EnsureStrictModeSatisfied(context.Model);

        // The tenant is resolved per save, only when there is something to encrypt, and never cached.
        TenantId? tenant = null;

        foreach (var entry in context.ChangeTracker.Entries())
        {
            if (entry.State is not (EntityState.Added or EntityState.Modified))
            {
                continue;
            }

            var metadata = EncryptedModelMetadata.Find(entry.Metadata);
            if (metadata is null || !metadata.HasEncryptedProperties)
            {
                continue;
            }

            tenant ??= _tenantResolver.Resolve(_serviceProvider);

            foreach (var descriptor in metadata.Properties)
            {
                EncryptProperty(entry, descriptor, tenant);
            }
        }
    }

    private void EncryptProperty(EntityEntry entry, EncryptedPropertyDescriptor descriptor, TenantId tenant)
    {
        var valueProperty = entry.Property(descriptor.PropertyName);

        // Process every property of an added entity, but only the changed properties of a modified
        // one. After a save the encrypted value is the unchanged original, so a re-save re-encrypts
        // nothing.
        if (entry.State == EntityState.Modified && !valueProperty.IsModified)
        {
            return;
        }

        var current = valueProperty.CurrentValue;
        if (current is null)
        {
            // null -> null: no envelope; clear any blind index that may have been set before.
            if (descriptor.IsSearchable)
            {
                entry.Property(descriptor.IndexPropertyName!).CurrentValue = null;
            }

            return;
        }

        var encryptionContext = new EncryptionContext(tenant, descriptor.Scope);
        var isStringProperty = descriptor.PropertyType == typeof(string);

        // Refuse to encrypt a value that is already a Proteos envelope: doing so would produce
        // Encrypt(Base64(Encrypt(...))) and silently corrupt the data. Detection is structural (the
        // codec must parse a complete, valid envelope), never a Base64/heuristic guess, so genuine
        // plaintext is never misread. This is a hard failure, not a silent correction.
        if (EncryptedEnvelopeDetector.IsEncryptedEnvelope(current, isStringProperty, _codec))
        {
            throw new AlreadyEncryptedValueException(entry.Metadata.ClrType, descriptor.PropertyName);
        }

        var plaintextBytes = isStringProperty ? Encoding.UTF8.GetBytes((string)current) : (byte[])current;

        var envelope = _encryptionService.EncryptToBytes(plaintextBytes, encryptionContext);
        valueProperty.CurrentValue = isStringProperty ? Convert.ToBase64String(envelope) : envelope;

        if (descriptor.IsSearchable)
        {
            // Searchable is string-only (enforced by the scanner): index the normalized plaintext.
            entry.Property(descriptor.IndexPropertyName!).CurrentValue = ComputeBlindIndex((string)current, descriptor, encryptionContext);
        }
    }

    private void EnsureStrictModeSatisfied(IModel model)
    {
        if (!_runtimeOptions.StrictMode)
        {
            return;
        }

        var report = EncryptedModelMetadata.FindAuditReport(model);
        if (report is { Unclassified.Count: > 0 })
        {
            throw new StrictModeViolationException(report.Unclassified);
        }
    }

    private byte[] ComputeBlindIndex(string plaintext, EncryptedPropertyDescriptor descriptor, EncryptionContext context)
    {
        var normalizer = BlindIndexNormalizerResolver.Resolve(descriptor.NormalizerKind!.Value);
        var normalized = normalizer.Normalize(plaintext);
        return _blindIndexProvider.Compute(Encoding.UTF8.GetBytes(normalized), BlindIndexDescriptor.ExactMatch, context).ToArray();
    }
}
