using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Configures Proteos encryption during DI registration. Exactly one key provider and one tenant
/// resolver must be set; both are validated when <c>AddProteosEncryption</c> runs, so a
/// misconfiguration fails at startup rather than at the first encrypt/decrypt operation.
/// </summary>
public sealed class ProteosEncryptionOptions
{
    private Func<IServiceProvider, IKeyMaterialProvider>? _keyProviderFactory;
    private Func<IServiceProvider, TenantId?>? _tenantResolver;
    private bool _strictMode;

    /// <summary>
    /// Uses the development-only key provider, optionally with an explicit root key. The root key
    /// is validated immediately (a too-short key throws here, not at first use). Never use this in
    /// production.
    /// </summary>
    public ProteosEncryptionOptions UseLocalDevelopmentKeyProvider(byte[]? rootKey = null)
    {
        EnsureKeyProviderNotConfigured();

        var provider = rootKey is null
            ? LocalDevelopmentKeyProvider.CreateWithDefaultDevelopmentRootKey()
            : new LocalDevelopmentKeyProvider(rootKey);

        _keyProviderFactory = _ => provider;
        return this;
    }

    /// <summary>
    /// Uses a custom key material provider, resolved from the service provider — for example a
    /// rotating development provider, or later a KMS-backed one. This is the single seam for any
    /// non-default provider; the rest of the stack stays provider-agnostic.
    /// </summary>
    /// <exception cref="ArgumentNullException">The factory is null.</exception>
    /// <exception cref="InvalidOperationException">A key provider is already configured.</exception>
    public ProteosEncryptionOptions UseKeyProvider(Func<IServiceProvider, IKeyMaterialProvider> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        EnsureKeyProviderNotConfigured();

        _keyProviderFactory = factory;
        return this;
    }

    /// <summary>Resolves the tenant per operation from the service provider. A null result is a hard error at runtime.</summary>
    public ProteosEncryptionOptions UseTenant(Func<IServiceProvider, TenantId?> tenantResolver)
    {
        ArgumentNullException.ThrowIfNull(tenantResolver);
        EnsureTenantNotConfigured();

        _tenantResolver = tenantResolver;
        return this;
    }

    /// <summary>Resolves the tenant per operation as a string; null/whitespace is treated as "no tenant" (hard error).</summary>
    public ProteosEncryptionOptions UseTenant(Func<IServiceProvider, string?> tenantResolver)
    {
        ArgumentNullException.ThrowIfNull(tenantResolver);

        return UseTenant(services =>
        {
            var value = tenantResolver(services);
            return string.IsNullOrWhiteSpace(value) ? null : new TenantId(value);
        });
    }

    /// <summary>Pins a single fixed tenant (single-tenant deployments). The id is validated immediately.</summary>
    public ProteosEncryptionOptions UseSingleTenant(string tenantId)
    {
        var tenant = new TenantId(tenantId);
        return UseTenant(_ => tenant);
    }

    /// <summary>
    /// Requires every string and byte[] property to be explicitly classified (encrypted, searchable,
    /// email or plaintext). An unclassified property then fails the save with an aggregated error
    /// listing all of them. There are no name heuristics, blacklists or silent defaults.
    /// </summary>
    public ProteosEncryptionOptions EnableStrictMode()
    {
        _strictMode = true;
        return this;
    }

    internal bool StrictMode => _strictMode;

    internal Func<IServiceProvider, IKeyMaterialProvider> KeyProviderFactory => _keyProviderFactory!;

    internal ITenantResolver BuildTenantResolver() => new DelegateTenantResolver(_tenantResolver!);

    internal void Validate()
    {
        if (_keyProviderFactory is null)
        {
            throw new InvalidOperationException(
                "Proteos encryption: no key provider configured. Call UseLocalDevelopmentKeyProvider() for development, or configure a KMS provider.");
        }

        if (_tenantResolver is null)
        {
            throw new InvalidOperationException(
                "Proteos encryption: no tenant resolver configured. Call UseTenant(...) or UseSingleTenant(...).");
        }
    }

    private void EnsureKeyProviderNotConfigured()
    {
        if (_keyProviderFactory is not null)
        {
            throw new InvalidOperationException("Proteos encryption: a key provider is already configured.");
        }
    }

    private void EnsureTenantNotConfigured()
    {
        if (_tenantResolver is not null)
        {
            throw new InvalidOperationException("Proteos encryption: a tenant resolver is already configured.");
        }
    }
}
