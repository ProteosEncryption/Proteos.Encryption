using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Resolves the tenant for the current operation. Implementations read the tenant from the
/// supplied (per-operation) service provider — never from a cached or global value — so a pooled
/// <c>DbContext</c> always uses the tenant of the current request. If no tenant can be resolved,
/// the call fails; there is no silent default.
/// </summary>
public interface ITenantResolver
{
    /// <summary>Resolves the tenant from the current scope.</summary>
    /// <exception cref="ProteosEncryptionException">No tenant could be resolved.</exception>
    TenantId Resolve(IServiceProvider services);
}
