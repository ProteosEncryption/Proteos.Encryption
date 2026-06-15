using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// <see cref="ITenantResolver"/> backed by the delegate configured via
/// <c>ProteosEncryptionOptions.UseTenant</c>. The delegate is invoked per operation with the
/// current service provider; a null result is turned into a hard error rather than a default.
/// </summary>
internal sealed class DelegateTenantResolver : ITenantResolver
{
    private readonly Func<IServiceProvider, TenantId?> _resolve;

    public DelegateTenantResolver(Func<IServiceProvider, TenantId?> resolve)
    {
        _resolve = resolve ?? throw new ArgumentNullException(nameof(resolve));
    }

    public TenantId Resolve(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);

        return _resolve(services)
            ?? throw new ProteosEncryptionException(
                "No tenant could be resolved for the current operation. A tenant is required for every encrypt/decrypt operation; there is no default tenant.");
    }
}
