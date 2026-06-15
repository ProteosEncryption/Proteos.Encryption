using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.EntityFrameworkCore;

namespace Microsoft.EntityFrameworkCore;

/// <summary>
/// Wires the Proteos encryption interceptor into a <see cref="DbContext"/>. Lives in the
/// <c>Microsoft.EntityFrameworkCore</c> namespace so it sits next to <c>UseSqlServer</c> etc.
/// </summary>
public static class ProteosEncryptionDbContextOptionsExtensions
{
    /// <summary>
    /// Adds the save-changes encryption interceptor, resolved from the given (scoped) service
    /// provider. Use the <c>AddDbContext((sp, options) =&gt; ...)</c> overload so the interceptor —
    /// and therefore the per-operation tenant resolution — runs in the current request scope:
    /// <c>options.UseProteosEncryption(sp)</c>. Call <c>modelBuilder.UseProteosEncryptionModel()</c>
    /// in <c>OnModelCreating</c> as well, to create the blind index columns.
    /// </summary>
    public static DbContextOptionsBuilder UseProteosEncryption(this DbContextOptionsBuilder optionsBuilder, IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(optionsBuilder);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        optionsBuilder.AddInterceptors(
            serviceProvider.GetRequiredService<EncryptingSaveChangesInterceptor>(),
            serviceProvider.GetRequiredService<DecryptingMaterializationInterceptor>());
        return optionsBuilder;
    }
}
