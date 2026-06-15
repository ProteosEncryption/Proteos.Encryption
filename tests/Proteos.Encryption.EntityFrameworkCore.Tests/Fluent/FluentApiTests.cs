using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Fluent;

// A plain POCO with no encryption attributes: everything is configured through the fluent API.
internal sealed class FluentCustomer
{
    public int Id { get; set; }
    public string? Email { get; set; }
    public string Alias { get; set; } = "";
    public string Phone { get; set; } = "";
    public byte[] Ssn { get; set; } = [];
    public string PlainName { get; set; } = "";
}

internal sealed class GuardEntity
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
}

// Carries an attribute, so the merge with fluent can be exercised (identical -> ok, different -> error).
[EncryptedEntity("customer")]
internal sealed class AttributedCustomer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]
    public string? Email { get; set; }
}

internal static class FluentConfigurations
{
    public static void Customer(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<FluentCustomer>().IsEncryptedEntity("customer");
        entity.Property(x => x.Email).IsEncryptedEmail("email");
        entity.Property(x => x.Alias).IsEncryptedSearchable("alias");
        entity.Property(x => x.Phone).IsEncrypted("phone");
        entity.Property(x => x.Ssn).IsEncrypted("ssn");
        modelBuilder.UseProteosEncryptionModel();
    }
}

internal sealed class FluentSqliteContext : DbContext
{
    public FluentSqliteContext(DbContextOptions<FluentSqliteContext> options)
        : base(options)
    {
    }

    public DbSet<FluentCustomer> Customers => Set<FluentCustomer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) => FluentConfigurations.Customer(modelBuilder);
}

public sealed class FluentApiEquivalenceTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;

    public FluentApiEquivalenceTests()
    {
        _connection = new SqliteConnection("Filename=:memory:");
        _connection.Open();

        _provider = new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                o.UseSingleTenant("acme");
            })
            .AddDbContext<FluentSqliteContext>((sp, options) => options
                .UseSqlite(_connection)
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();

        using var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<FluentSqliteContext>().Database.EnsureCreated();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
    }

    private FluentSqliteContext NewContext(IServiceScope scope) => scope.ServiceProvider.GetRequiredService<FluentSqliteContext>();

    [Fact]
    public void Fluent_ConfiguresSameShadowIndexModelAsAttributes()
    {
        using var scope = _provider.CreateScope();
        var entity = NewContext(scope).Model.FindEntityType(typeof(FluentCustomer))!;

        Assert.True(entity.FindProperty("EmailIndex")!.IsShadowProperty());
        Assert.True(entity.FindProperty("AliasIndex")!.IsShadowProperty());
        Assert.Null(entity.FindProperty("PhoneIndex"));
        Assert.Null(entity.FindProperty("SsnIndex"));

        var emailIndex = entity.GetIndexes().Single(i => i.Properties.Count == 1 && i.Properties[0].Name == "EmailIndex");
        Assert.False(emailIndex.IsUnique);
        Assert.Equal(32, entity.FindProperty("EmailIndex")!.GetMaxLength());
    }

    [Fact]
    public void Fluent_Roundtrip_EncryptsAndDecrypts()
    {
        using (var scope = _provider.CreateScope())
        {
            var context = NewContext(scope);
            var customer = new FluentCustomer { Email = "max@example.com", Alias = "mx", Phone = "+49123", Ssn = [1, 2, 3], PlainName = "Max" };
            context.Customers.Add(customer);
            context.SaveChanges();

            Assert.NotEqual("max@example.com", customer.Email); // encrypted in place by the save interceptor
        }

        using (var scope = _provider.CreateScope())
        {
            var loaded = NewContext(scope).Customers.Single();

            Assert.Equal("max@example.com", loaded.Email);
            Assert.Equal("mx", loaded.Alias);
            Assert.Equal("+49123", loaded.Phone);
            Assert.Equal(new byte[] { 1, 2, 3 }, loaded.Ssn);
            Assert.Equal("Max", loaded.PlainName);
        }
    }

    [Fact]
    public void Fluent_Query_FindsByBlindIndex()
    {
        using (var scope = _provider.CreateScope())
        {
            var context = NewContext(scope);
            context.Customers.Add(new FluentCustomer { Email = "max@example.com", Alias = "mx", Phone = "p", PlainName = "Max" });
            context.Customers.Add(new FluentCustomer { Email = "other@example.com", Alias = "ot", Phone = "q", PlainName = "Other" });
            context.SaveChanges();
        }

        using (var scope = _provider.CreateScope())
        {
            var context = NewContext(scope);

            var found = context.Customers.WhereEncryptedEquals(context, x => x.Email, "max@example.com").ToList();
            Assert.Single(found);
            Assert.Equal("Max", found[0].PlainName);

            Assert.Empty(context.Customers.WhereEncryptedEquals(context, x => x.Email, "nobody@example.com").ToList());
        }
    }
}

public sealed class FluentApiMergeAndGuardTests
{
    private abstract class InMemoryModelContext : DbContext
    {
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
            optionsBuilder
                .UseInMemoryDatabase("proteos-fluent-" + GetType().Name)
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning));
    }

    // Attribute [EncryptedEmail("email")] plus an identical fluent configuration: allowed.
    private sealed class IdenticalAttributeAndFluentContext : InMemoryModelContext
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AttributedCustomer>().Property(x => x.Email).IsEncryptedEmail("email");
            modelBuilder.UseProteosEncryptionModel();
        }
    }

    // Attribute says searchable "email"; fluent says encrypted-only "primary": a conflict.
    private sealed class ConflictingPropertyContext : InMemoryModelContext
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AttributedCustomer>().Property(x => x.Email).IsEncrypted("primary");
            modelBuilder.UseProteosEncryptionModel();
        }
    }

    // Attribute entity name "customer"; fluent entity name "client": a conflict.
    private sealed class ConflictingEntityNameContext : InMemoryModelContext
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AttributedCustomer>().IsEncryptedEntity("client");
            modelBuilder.UseProteosEncryptionModel();
        }
    }

    // The same property configured twice through fluent.
    private sealed class DoubleFluentConfigContext : InMemoryModelContext
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var entity = modelBuilder.Entity<FluentCustomer>().IsEncryptedEntity("customer");
            entity.Property(x => x.Email).IsEncrypted("email");
            entity.Property(x => x.Email).IsEncryptedSearchable("email");
            modelBuilder.UseProteosEncryptionModel();
        }
    }

    // Fluent encrypts a property but no entity logical name is given anywhere.
    private sealed class MissingEntityNameContext : InMemoryModelContext
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<FluentCustomer>().Property(x => x.Email).IsEncrypted("email");
            modelBuilder.UseProteosEncryptionModel();
        }
    }

    [Fact]
    public void AttributeAndIdenticalFluent_IsAllowed()
    {
        using var context = new IdenticalAttributeAndFluentContext();

        var entity = context.Model.FindEntityType(typeof(AttributedCustomer))!;
        Assert.True(entity.FindProperty("EmailIndex")!.IsShadowProperty());
    }

    [Fact]
    public void AttributeAndConflictingFluentProperty_IsHardError()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() =>
        {
            using var context = new ConflictingPropertyContext();
            _ = context.Model;
        });
    }

    [Fact]
    public void AttributeAndConflictingFluentEntityName_IsHardError()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() =>
        {
            using var context = new ConflictingEntityNameContext();
            _ = context.Model;
        });
    }

    [Fact]
    public void DoubleFluentConfiguration_IsHardError()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var context = new DoubleFluentConfigContext();
            _ = context.Model;
        });
    }

    [Fact]
    public void FluentWithoutEntityName_IsHardError()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() =>
        {
            using var context = new MissingEntityNameContext();
            _ = context.Model;
        });
    }

    [Fact]
    public void MissingModelConvention_SaveIsHardError()
    {
        using var connection = new SqliteConnection("Filename=:memory:");
        connection.Open();
        using var provider = new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                o.UseSingleTenant("acme");
            })
            .AddDbContext<MissingConventionContext>((sp, options) => options
                .UseSqlite(connection)
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();

        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<MissingConventionContext>();
        context.Database.EnsureCreated();
        context.Items.Add(new GuardEntity { Name = "x" });

        // The interceptor is wired but UseProteosEncryptionModel() was never called: save must fail loudly.
        Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
    }
}

internal sealed class MissingConventionContext : DbContext
{
    public MissingConventionContext(DbContextOptions<MissingConventionContext> options)
        : base(options)
    {
    }

    public DbSet<GuardEntity> Items => Set<GuardEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.Entity<GuardEntity>();
    // Deliberately does NOT call UseProteosEncryptionModel().
}
