using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Query;

internal sealed class RotationContext : DbContext
{
    public RotationContext(DbContextOptions<RotationContext> options)
        : base(options)
    {
    }

    public DbSet<ValidCustomer> Customers => Set<ValidCustomer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ValidCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

// Real key rotation across a shared SQLite database: each write happens under a provider whose
// current version differs, so rows end up with blind indexes (and ciphertext) from different key
// versions. The search then has to find them all.
public sealed class RotationAwareSearchTests : IDisposable
{
    private static readonly byte[] R1 = Enumerable.Repeat((byte)0x11, 32).ToArray();
    private static readonly byte[] R2 = Enumerable.Repeat((byte)0x22, 32).ToArray();
    private static readonly byte[] R3 = Enumerable.Repeat((byte)0x33, 32).ToArray();

    private readonly SqliteConnection _connection;

    public RotationAwareSearchTests()
    {
        _connection = new SqliteConnection("Filename=:memory:");
        _connection.Open();

        using var provider = BuildProvider(currentVersion: 1, V(1, R1));
        using var scope = provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<RotationContext>().Database.EnsureCreated();
    }

    public void Dispose() => _connection.Dispose();

    private static LocalDevelopmentKeyVersion V(ushort version, byte[] rootKey) => new(version, rootKey);

    private ServiceProvider BuildProvider(ushort currentVersion, params LocalDevelopmentKeyVersion[] versions) =>
        new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseKeyProvider(_ => LocalDevelopmentKeyProvider.CreateRotating(versions, currentVersion));
                o.UseSingleTenant("acme");
            })
            .AddDbContext<RotationContext>((sp, options) => options
                .UseSqlite(_connection)
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();

    private void Save(string label, ushort currentVersion, params LocalDevelopmentKeyVersion[] versions)
    {
        using var provider = BuildProvider(currentVersion, versions);
        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<RotationContext>();
        context.Customers.Add(new ValidCustomer { Email = "max@example.com", PlainName = label });
        context.SaveChanges();
    }

    private List<ValidCustomer> Search(ushort currentVersion, params LocalDevelopmentKeyVersion[] versions)
    {
        using var provider = BuildProvider(currentVersion, versions);
        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<RotationContext>();
        return context.Customers
            .WhereEncryptedEquals(context, x => x.Email, "max@example.com")
            .OrderBy(x => x.PlainName)
            .ToList();
    }

    [Fact]
    public void Search_FindsRowsWrittenUnderEveryKeyVersion()
    {
        Save("A", currentVersion: 1, V(1, R1));               // index + ciphertext under v1
        Save("B", currentVersion: 2, V(1, R1), V(2, R2));     // under v2
        Save("C", currentVersion: 3, V(1, R1), V(2, R2), V(3, R3)); // under v3

        var found = Search(currentVersion: 3, V(1, R1), V(2, R2), V(3, R3));

        Assert.Equal(new[] { "A", "B", "C" }, found.Select(c => c.PlainName));
        Assert.All(found, c => Assert.Equal("max@example.com", c.Email)); // each decrypts via its own version
    }

    [Fact]
    public void Search_WithCurrentOnlyProvider_FindsOnlyCurrentVersionData_AndDoesNotThrow()
    {
        Save("A", currentVersion: 1, V(1, R1));
        Save("B", currentVersion: 2, V(1, R1), V(2, R2));
        Save("C", currentVersion: 3, V(1, R1), V(2, R2), V(3, R3));

        // This provider knows only v3: it can search and decrypt v3 data; older versions are ignored.
        var found = Search(currentVersion: 3, V(3, R3));

        Assert.Equal(new[] { "C" }, found.Select(c => c.PlainName));
        Assert.Equal("max@example.com", found[0].Email);
    }
}
