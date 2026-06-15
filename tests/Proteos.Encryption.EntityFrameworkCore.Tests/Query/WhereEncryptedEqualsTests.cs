using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Query;

internal sealed class QueryContext : DbContext
{
    public QueryContext(DbContextOptions<QueryContext> options)
        : base(options)
    {
    }

    public DbSet<CustomerMultiple> Multiple => Set<CustomerMultiple>();

    public DbSet<ValidCustomer> Shadow => Set<ValidCustomer>();

    public DbSet<CustomerWithExplicitIndex> Explicit => Set<CustomerWithExplicitIndex>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<CustomerMultiple>();
        modelBuilder.Entity<ValidCustomer>();
        modelBuilder.Entity<CustomerWithExplicitIndex>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

// Real SQL translation matters here, so these tests run against SQLite (an actual relational
// provider) rather than the in-memory provider: a predicate that could not translate would throw
// on enumeration instead of silently falling back to client evaluation.
public sealed class WhereEncryptedEqualsTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;

    public WhereEncryptedEqualsTests()
        : this(o => o.UseSingleTenant("acme"))
    {
    }

    private WhereEncryptedEqualsTests(Action<ProteosEncryptionOptions> configureTenant)
    {
        _connection = new SqliteConnection("Filename=:memory:");
        _connection.Open();

        _provider = new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                configureTenant(o);
            })
            .AddDbContext<QueryContext>((sp, options) => options
                .UseSqlite(_connection)
                // Each test builds its own root provider, so EF caches one internal provider per
                // test; that is expected test isolation, not the production misuse this warns about.
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();

        using var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<QueryContext>().Database.EnsureCreated();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _connection.Dispose();
    }

    private void Seed(Action<QueryContext> seed)
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();
        seed(context);
        context.SaveChanges();
    }

    private List<T> Query<T>(Func<QueryContext, IQueryable<T>> query)
    {
        // A fresh scope means a fresh change tracker, so the rows are materialized (and decrypted)
        // from the database rather than served from the identity map of the seeding context.
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();
        return query(context).ToList();
    }

    [Fact]
    public void Equality_FindsTheMatchingRecord()
    {
        Seed(c =>
        {
            c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "mx", Phone = "p1", PlainName = "Max" });
            c.Multiple.Add(new CustomerMultiple { Email = "other@example.com", Alias = "ot", Phone = "p2", PlainName = "Other" });
        });

        var found = Query(c => c.Multiple.WhereEncryptedEquals(c, x => x.Email, "max@example.com"));

        Assert.Single(found);
        Assert.Equal("max@example.com", found[0].Email);
        Assert.Equal("Max", found[0].PlainName);
    }

    [Fact]
    public void Equality_NormalizesTheSearchTerm()
    {
        Seed(c => c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "mx", Phone = "p", PlainName = "Max" }));

        // The email normalizer lower-cases and trims, so a differently-cased, padded term still matches.
        var found = Query(c => c.Multiple.WhereEncryptedEquals(c, x => x.Email, "  MAX@Example.COM  "));

        Assert.Single(found);
    }

    [Fact]
    public void Equality_WrongValue_FindsNothing()
    {
        Seed(c => c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "mx", Phone = "p", PlainName = "Max" }));

        var found = Query(c => c.Multiple.WhereEncryptedEquals(c, x => x.Email, "nobody@example.com"));

        Assert.Empty(found);
    }

    [Fact]
    public void MultipleConditions_AreCombinedWithAnd()
    {
        Seed(c =>
        {
            c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "mx", Phone = "p1", PlainName = "Max" });
            c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "other", Phone = "p2", PlainName = "Clash" });
        });

        var found = Query(c => c.Multiple
            .WhereEncryptedEquals(c, x => x.Email, "max@example.com")
            .WhereEncryptedEquals(c, x => x.Alias, "mx"));

        Assert.Single(found);
        Assert.Equal("Max", found[0].PlainName);
    }

    [Fact]
    public void ShadowIndexProperty_IsSearchable_WithoutAClrProperty()
    {
        Seed(c => c.Shadow.Add(new ValidCustomer { Email = "shadow@example.com", Phone = "p", Ssn = [1] }));

        var found = Query(c => c.Shadow.WhereEncryptedEquals(c, x => x.Email, "shadow@example.com"));

        Assert.Single(found);
        Assert.Equal("shadow@example.com", found[0].Email);
    }

    [Fact]
    public void ExplicitClrIndexProperty_IsSearchable()
    {
        Seed(c => c.Explicit.Add(new CustomerWithExplicitIndex { Email = "explicit@example.com" }));

        var found = Query(c => c.Explicit.WhereEncryptedEquals(c, x => x.Email, "explicit@example.com"));

        Assert.Single(found);
        Assert.Equal("explicit@example.com", found[0].Email);
    }

    [Fact]
    public void NullValue_IsAHardError()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        Assert.Throws<ArgumentNullException>(() => context.Multiple.WhereEncryptedEquals(context, x => x.Email, null));
    }

    [Fact]
    public void InvalidExpression_IsRejected()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        Assert.Throws<ArgumentException>(() => context.Multiple.WhereEncryptedEquals(context, x => x.Email.Trim(), "x"));
    }

    [Fact]
    public void NonSearchableProperty_IsRejected()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        // Phone is [Encrypted] but not searchable: there is no blind index column to filter.
        Assert.Throws<ArgumentException>(() => context.Multiple.WhereEncryptedEquals(context, x => x.Phone, "p"));
    }

    [Fact]
    public void NonEncryptedProperty_IsRejected()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        Assert.Throws<ArgumentException>(() => context.Multiple.WhereEncryptedEquals(context, x => x.PlainName, "Max"));
    }

    [Fact]
    public void Predicate_TranslatesToSql_OnTheIndexColumn_WithoutLeakingThePlaintext()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        var query = context.Multiple.WhereEncryptedEquals(context, x => x.Email, "max@example.com");
        var sql = query.ToQueryString();

        Assert.Contains("EmailIndex", sql);
        Assert.Contains("@", sql); // the blind index is a parameter, not an inlined literal
        Assert.DoesNotContain("max@example.com", sql);

        // Enumerating proves the predicate is server-translatable: SQLite throws on a Where that
        // would require client evaluation, so reaching a result at all rules it out.
        Assert.Empty(query.ToList());
    }

    [Fact]
    public void MissingTenant_IsAHardError()
    {
        using var tenantlessConnection = new SqliteConnection("Filename=:memory:");
        tenantlessConnection.Open();
        using var provider = new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                o.UseTenant(_ => (TenantId?)null);
            })
            .AddDbContext<QueryContext>((sp, options) => options
                .UseSqlite(tenantlessConnection)
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();

        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();
        context.Database.EnsureCreated();

        Assert.Throws<ProteosEncryptionException>(() => context.Multiple.WhereEncryptedEquals(context, x => x.Email, "max@example.com"));
    }

    [Fact]
    public void In_FindsAllMatchingRecords()
    {
        Seed(c =>
        {
            c.Multiple.Add(new CustomerMultiple { Email = "a@example.com", Alias = "a", Phone = "p", PlainName = "A" });
            c.Multiple.Add(new CustomerMultiple { Email = "b@example.com", Alias = "b", Phone = "p", PlainName = "B" });
            c.Multiple.Add(new CustomerMultiple { Email = "c@example.com", Alias = "c", Phone = "p", PlainName = "C" });
        });

        var found = Query(c => c.Multiple.WhereEncryptedIn(c, x => x.Email, new[] { "a@example.com", "c@example.com" }));

        Assert.Equal(2, found.Count);
        Assert.Contains(found, x => x.PlainName == "A");
        Assert.Contains(found, x => x.PlainName == "C");
    }

    [Fact]
    public void In_NormalizesEachTerm()
    {
        Seed(c => c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "mx", Phone = "p", PlainName = "Max" }));

        // The email normalizer lower-cases and trims each term, so a differently-cased, padded term still matches.
        var found = Query(c => c.Multiple.WhereEncryptedIn(c, x => x.Email, new[] { "  MAX@Example.com ", "nobody@example.com" }));

        Assert.Single(found);
    }

    [Fact]
    public void In_EmptyValues_FindsNothing()
    {
        Seed(c => c.Multiple.Add(new CustomerMultiple { Email = "a@example.com", Alias = "a", Phone = "p", PlainName = "A" }));

        var found = Query(c => c.Multiple.WhereEncryptedIn(c, x => x.Email, Array.Empty<string>()));

        Assert.Empty(found);
    }

    [Fact]
    public void In_NullCollection_IsAHardError()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        Assert.Throws<ArgumentNullException>(() => context.Multiple.WhereEncryptedIn(context, x => x.Email, null!));
    }

    [Fact]
    public void In_NullValueInCollection_IsAHardError()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        var values = new string[] { "a@example.com", null! };
        Assert.Throws<ArgumentException>(() => context.Multiple.WhereEncryptedIn(context, x => x.Email, values));
    }

    [Fact]
    public void In_TranslatesToSql_WithoutLeakingThePlaintext()
    {
        using var scope = _provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<QueryContext>();

        var query = context.Multiple.WhereEncryptedIn(context, x => x.Email, new[] { "a@example.com", "b@example.com" });
        var sql = query.ToQueryString();

        Assert.Contains("EmailIndex", sql);
        Assert.DoesNotContain("a@example.com", sql);
        Assert.DoesNotContain("b@example.com", sql);

        // Enumerating proves the predicate is server-translatable (SQLite throws on client evaluation).
        Assert.Empty(query.ToList());
    }

    [Fact]
    public void Email_Wrapper_FindsTheMatchingRecord()
    {
        Seed(c => c.Multiple.Add(new CustomerMultiple { Email = "max@example.com", Alias = "mx", Phone = "p", PlainName = "Max" }));

        var found = Query(c => c.Multiple.WhereEncryptedEmail(c, x => x.Email, "max@example.com"));

        Assert.Single(found);
        Assert.Equal("Max", found[0].PlainName);
    }
}
