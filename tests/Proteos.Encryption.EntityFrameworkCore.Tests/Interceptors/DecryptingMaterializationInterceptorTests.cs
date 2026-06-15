using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Interceptors;

internal sealed class RoundtripContext : DbContext
{
    private readonly IInterceptor[] _interceptors;
    private readonly string _databaseName;
    private readonly InMemoryDatabaseRoot _root;

    public RoundtripContext(IEnumerable<IInterceptor> interceptors, string databaseName, InMemoryDatabaseRoot root)
    {
        _interceptors = interceptors.ToArray();
        _databaseName = databaseName;
        _root = root;
    }

    public DbSet<ValidCustomer> Customers => Set<ValidCustomer>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
        optionsBuilder
            .UseInMemoryDatabase(_databaseName, _root)
            .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
            .AddInterceptors(_interceptors);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ValidCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

public sealed class DecryptingMaterializationInterceptorTests
{
    private static (EncryptingSaveChangesInterceptor Save, DecryptingMaterializationInterceptor Read) Interceptors(string tenant = "acme")
    {
        var services = new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                o.UseSingleTenant(tenant);
            })
            .BuildServiceProvider()
            .CreateScope()
            .ServiceProvider;

        return (services.GetRequiredService<EncryptingSaveChangesInterceptor>(), services.GetRequiredService<DecryptingMaterializationInterceptor>());
    }

    [Fact]
    public void Roundtrip_DecryptsStringAndByteArrayProperties()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();
        var (save, read) = Interceptors();
        using var context = new RoundtripContext([save, read], name, root);
        context.Add(new ValidCustomer { Email = "max@example.com", Phone = "+4912345", Ssn = [1, 2, 3] });
        context.SaveChanges();
        context.ChangeTracker.Clear();

        var loaded = context.Customers.Single();

        Assert.Equal("max@example.com", loaded.Email);
        Assert.Equal("+4912345", loaded.Phone);
        Assert.Equal(new byte[] { 1, 2, 3 }, loaded.Ssn);
    }

    [Fact]
    public void Roundtrip_NullStaysNull()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();
        var (save, read) = Interceptors();
        using var context = new RoundtripContext([save, read], name, root);
        context.Add(new ValidCustomer { Email = null, Phone = "x", Ssn = [] });
        context.SaveChanges();
        context.ChangeTracker.Clear();

        var loaded = context.Customers.Single();

        Assert.Null(loaded.Email);
        Assert.Equal("x", loaded.Phone);
    }

    [Fact]
    public void AfterLoad_EntityIsNotModified_AndSaveDoesNotReEncrypt()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();
        var (save, read) = Interceptors();
        using var context = new RoundtripContext([save, read], name, root);
        context.Add(new ValidCustomer { Email = "max@example.com", Phone = "p", Ssn = [1] });
        context.SaveChanges();
        context.ChangeTracker.Clear();

        var loaded = context.Customers.Single();

        Assert.Equal(EntityState.Unchanged, context.Entry(loaded).State);

        context.SaveChanges(); // must not re-encrypt an unchanged, already-decrypted entity

        Assert.Equal("max@example.com", loaded.Email);
    }

    [Fact]
    public void MultipleEntities_AreAllDecrypted()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();
        var (save, read) = Interceptors();
        using var context = new RoundtripContext([save, read], name, root);
        context.AddRange(
            new ValidCustomer { Email = "a@b.com", Phone = "1", Ssn = [1] },
            new ValidCustomer { Email = "c@d.com", Phone = "2", Ssn = [2] });
        context.SaveChanges();
        context.ChangeTracker.Clear();

        // Materialize full entities (the interceptor decrypts on materialization), then project in memory.
        var emails = context.Customers.ToList().Select(c => c.Email).OrderBy(e => e).ToList();

        Assert.Equal(new[] { "a@b.com", "c@d.com" }, emails);
    }

    [Fact]
    public void WrongTenant_FailsToDecrypt()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();

        var (saveAcme, readAcme) = Interceptors("acme");
        using (var acme = new RoundtripContext([saveAcme, readAcme], name, root))
        {
            acme.Add(new ValidCustomer { Email = "max@example.com", Phone = "p", Ssn = [1] });
            acme.SaveChanges();
        }

        var (saveGlobex, readGlobex) = Interceptors("globex");
        using var globex = new RoundtripContext([saveGlobex, readGlobex], name, root);

        Assert.ThrowsAny<ProteosEncryptionException>(() => globex.Customers.ToList());
    }

    [Fact]
    public void InvalidBase64_FailsToDecrypt()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();

        // Insert raw, unencrypted data with no interceptors.
        using (var raw = new RoundtripContext([], name, root))
        {
            raw.Add(new ValidCustomer { Email = "this is not base64 ###", Phone = "p", Ssn = [1] });
            raw.SaveChanges();
        }

        var (_, read) = Interceptors();
        using var context = new RoundtripContext([read], name, root);

        Assert.ThrowsAny<ProteosEncryptionException>(() => context.Customers.ToList());
    }

    [Fact]
    public void ValidBase64ButInvalidEnvelope_FailsToDecrypt()
    {
        var root = new InMemoryDatabaseRoot();
        var name = Guid.NewGuid().ToString();

        using (var raw = new RoundtripContext([], name, root))
        {
            raw.Add(new ValidCustomer { Email = Convert.ToBase64String([1, 2, 3, 4]), Phone = "p", Ssn = [1] });
            raw.SaveChanges();
        }

        var (_, read) = Interceptors();
        using var context = new RoundtripContext([read], name, root);

        Assert.ThrowsAny<ProteosEncryptionException>(() => context.Customers.ToList());
    }
}
