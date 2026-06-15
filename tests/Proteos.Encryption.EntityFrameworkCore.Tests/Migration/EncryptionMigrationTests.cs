using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Migration;

internal sealed class MigrationContext : DbContext
{
    public MigrationContext(DbContextOptions<MigrationContext> options)
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

// A context with the model (so shadow index columns exist) but NO interceptors: it reads stored
// ciphertext as-is and writes pre-computed values as-is — the mechanism a re-encryption worker uses.
internal sealed class RawContext : DbContext
{
    private readonly SqliteConnection _connection;

    public RawContext(SqliteConnection connection) => _connection = connection;

    public DbSet<ValidCustomer> Customers => Set<ValidCustomer>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
        optionsBuilder
            .UseSqlite(_connection)
            .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning));

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ValidCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

public sealed class EncryptionMigrationTests
{
    private static readonly byte[] R1 = Enumerable.Repeat((byte)0x11, 32).ToArray();
    private static readonly byte[] R2 = Enumerable.Repeat((byte)0x22, 32).ToArray();
    private static readonly TenantId Tenant = new("acme");

    private static LocalDevelopmentKeyProvider V1() => LocalDevelopmentKeyProvider.CreateRotating([new(1, R1)], 1);

    private static LocalDevelopmentKeyProvider V2() => LocalDevelopmentKeyProvider.CreateRotating([new(1, R1), new(2, R2)], 2);

    private static AesGcmValueEncryptionService Service(IKeyMaterialProvider provider) => new(provider, new CiphertextEnvelopeCodec());

    private static EncryptionMigrationPlanner Planner(IKeyMaterialProvider provider) => new(new CiphertextEnvelopeCodec(), provider);

    private static EncryptionMigrationService Migration(IKeyMaterialProvider provider) => new(Service(provider), new HmacBlindIndexProvider(provider));

    private static EncryptedPropertyDescriptor Descriptor(string property) =>
        EncryptedEntityMetadataScanner.Scan(typeof(ValidCustomer)).Properties.Single(d => d.PropertyName == property);

    private static EncryptionContext ContextFor(EncryptedPropertyDescriptor descriptor) => new(Tenant, descriptor.Scope);

    private static string EncryptString(IKeyMaterialProvider provider, EncryptedPropertyDescriptor descriptor, string plaintext) =>
        Convert.ToBase64String(Service(provider).EncryptToBytes(Encoding.UTF8.GetBytes(plaintext), ContextFor(descriptor)));

    // --- Detection ---

    [Fact]
    public void NeedsReEncryption_V1ValueUnderCurrentV2_IsTrue()
    {
        var email = Descriptor("Email");
        var stored = EncryptString(V1(), email, "max@example.com");

        Assert.True(Planner(V2()).NeedsReEncryption(typeof(string), stored, V2().GetCurrentKeyId(Tenant)));
    }

    [Fact]
    public void NeedsReEncryption_V2ValueUnderCurrentV2_IsFalse()
    {
        var email = Descriptor("Email");
        var stored = EncryptString(V2(), email, "max@example.com");

        Assert.False(Planner(V2()).NeedsReEncryption(typeof(string), stored, V2().GetCurrentKeyId(Tenant)));
    }

    [Fact]
    public void NeedsReEncryption_NullValue_IsFalse()
    {
        Assert.False(Planner(V2()).NeedsReEncryption(typeof(string), null, V2().GetCurrentKeyId(Tenant)));
    }

    [Fact]
    public void ReadStoredKeyId_InvalidBase64_Throws()
    {
        Assert.ThrowsAny<ProteosEncryptionException>(() => Planner(V2()).ReadStoredKeyId(typeof(string), "not-base64-###"));
    }

    [Fact]
    public void ReadStoredKeyId_ValidBase64ButInvalidEnvelope_Throws()
    {
        Assert.ThrowsAny<ProteosEncryptionException>(() => Planner(V2()).ReadStoredKeyId(typeof(string), Convert.ToBase64String([1, 2, 3, 4])));
    }

    // --- Execution ---

    [Fact]
    public void ReEncrypt_StringProperty_ProducesCurrentKeyEnvelope_StillReadable()
    {
        var email = Descriptor("Email");
        var stored = EncryptString(V1(), email, "max@example.com");

        var migrated = Migration(V2()).ReEncrypt(email, stored, Tenant);

        var newValue = Assert.IsType<string>(migrated.NewValue);
        Assert.Equal(V2().GetCurrentKeyId(Tenant), Planner(V2()).ReadStoredKeyId(typeof(string), newValue));
        Assert.False(Planner(V2()).NeedsReEncryption(typeof(string), newValue, V2().GetCurrentKeyId(Tenant)));

        var plaintext = Service(V2()).DecryptFromBytes(Convert.FromBase64String(newValue), ContextFor(email));
        Assert.Equal("max@example.com", Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public void ReEncrypt_SearchableProperty_ReindexesWithCurrentKey()
    {
        var email = Descriptor("Email");
        var stored = EncryptString(V1(), email, "max@example.com");

        var migrated = Migration(V2()).ReEncrypt(email, stored, Tenant);

        Assert.Equal("EmailIndex", migrated.IndexPropertyName);
        var expected = new HmacBlindIndexProvider(V2())
            .Compute(Encoding.UTF8.GetBytes(EmailBlindIndexNormalizer.Instance.Normalize("max@example.com")), BlindIndexDescriptor.ExactMatch, ContextFor(email))
            .ToArray();
        Assert.Equal(expected, migrated.NewBlindIndex);
    }

    [Fact]
    public void ReEncrypt_ByteArrayProperty_ProducesCurrentKeyEnvelope_WithoutBlindIndex()
    {
        var ssn = Descriptor("Ssn");
        var stored = Service(V1()).EncryptToBytes(new byte[] { 9, 8, 7 }, ContextFor(ssn));

        var migrated = Migration(V2()).ReEncrypt(ssn, stored, Tenant);

        var newBytes = Assert.IsType<byte[]>(migrated.NewValue);
        Assert.Null(migrated.IndexPropertyName); // encrypted-only property has no blind index
        Assert.Null(migrated.NewBlindIndex);
        Assert.Equal(V2().GetCurrentKeyId(Tenant), Planner(V2()).ReadStoredKeyId(typeof(byte[]), newBytes));
        Assert.Equal(new byte[] { 9, 8, 7 }, Service(V2()).DecryptFromBytes(newBytes, ContextFor(ssn)));
    }

    // --- Plan ---

    [Fact]
    public void CreatePlan_ListsOnlyPropertiesUnderAnOlderVersion()
    {
        var metadata = EncryptedEntityMetadataScanner.Scan(typeof(ValidCustomer));
        var stored = new Dictionary<string, object?>
        {
            ["Email"] = EncryptString(V1(), Descriptor("Email"), "max@example.com"),                                      // v1 -> migrate
            ["Phone"] = EncryptString(V2(), Descriptor("Phone"), "+49123"),                                               // v2 -> keep
            ["Ssn"] = Service(V1()).EncryptToBytes(new byte[] { 1 }, ContextFor(Descriptor("Ssn"))),                       // v1 -> migrate
        };

        var plan = Planner(V2()).CreatePlan(metadata, stored, Tenant);

        Assert.True(plan.RequiresMigration);
        Assert.Equal(new[] { "Email", "Ssn" }, plan.PropertiesToMigrate.Select(p => p.Property.PropertyName).OrderBy(n => n));
        Assert.All(plan.PropertiesToMigrate, p => Assert.True(p.NeedsReEncryption));
    }

    [Fact]
    public void CreatePlan_AllCurrentOrNull_RequiresNoMigration()
    {
        var metadata = EncryptedEntityMetadataScanner.Scan(typeof(ValidCustomer));
        var stored = new Dictionary<string, object?>
        {
            ["Email"] = EncryptString(V2(), Descriptor("Email"), "max@example.com"), // current
            // Phone and Ssn absent -> treated as null -> skipped
        };

        var plan = Planner(V2()).CreatePlan(metadata, stored, Tenant);

        Assert.False(plan.RequiresMigration);
        Assert.Empty(plan.PropertiesToMigrate);
    }

    // --- Safety ---

    [Fact]
    public void ReEncrypt_InvalidEnvelope_Throws()
    {
        Assert.ThrowsAny<ProteosEncryptionException>(() => Migration(V2()).ReEncrypt(Descriptor("Email"), "invalid-###", Tenant));
    }

    [Fact]
    public void ReEncrypt_NullStoredValue_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Migration(V2()).ReEncrypt(Descriptor("Email"), null!, Tenant));
    }

    // --- End-to-end through EF (read raw, re-encrypt, write raw, search) ---

    [Fact]
    public void EndToEnd_MigratedRow_IsStoredUnderCurrentVersion_AndStillSearchable()
    {
        using var connection = new SqliteConnection("Filename=:memory:");
        connection.Open();

        using (var provider = BuildProvider(connection, V1()))
        using (var scope = provider.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<MigrationContext>();
            context.Database.EnsureCreated();
            context.Customers.Add(new ValidCustomer { Email = "max@example.com", PlainName = "Max" });
            context.SaveChanges(); // stored under v1
        }

        using (var v2 = BuildProvider(connection, V2()))
        using (var scope = v2.CreateScope())
        {
            var migration = scope.ServiceProvider.GetRequiredService<IEncryptionMigrationService>();
            using var raw = new RawContext(connection);
            var entity = raw.Customers.Single(); // raw ciphertext, no decryption
            var migrated = migration.ReEncrypt(Descriptor("Email"), entity.Email!, Tenant);
            entity.Email = (string)migrated.NewValue;
            raw.Entry(entity).Property("EmailIndex").CurrentValue = migrated.NewBlindIndex;
            raw.SaveChanges();
        }

        using (var raw = new RawContext(connection))
        {
            Assert.Equal(V2().GetCurrentKeyId(Tenant), Planner(V2()).ReadStoredKeyId(typeof(string), raw.Customers.Single().Email!));
        }

        using (var v2 = BuildProvider(connection, V2()))
        using (var scope = v2.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<MigrationContext>();
            var found = context.Customers.WhereEncryptedEquals(context, x => x.Email, "max@example.com").Single();
            Assert.Equal("max@example.com", found.Email);
            Assert.Equal("Max", found.PlainName);
        }
    }

    private static ServiceProvider BuildProvider(SqliteConnection connection, IKeyMaterialProvider keyProvider) =>
        new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseKeyProvider(_ => keyProvider);
                o.UseSingleTenant("acme");
            })
            .AddDbContext<MigrationContext>((sp, options) => options
                .UseSqlite(connection)
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();
}
