using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Audit;

[EncryptedEntity("customer")]
internal sealed class AuditCustomer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]
    public string Email { get; set; } = "";

    [Encrypted("phone")]
    public string Phone { get; set; } = "";

    [Encrypted("ssn")]
    public byte[] Ssn { get; set; } = [];

    [Plaintext]
    public string DisplayName { get; set; } = "";

    public string Notes { get; set; } = ""; // deliberately unclassified
}

[EncryptedEntity("emp")]
internal sealed class AuditEmployee
{
    public int Id { get; set; }

    [Encrypted("name")]
    public string Name { get; set; } = "";

    public string Iban { get; set; } = ""; // deliberately unclassified
}

[EncryptedEntity("clean")]
internal sealed class CleanCustomer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]
    public string Email { get; set; } = "";

    [Plaintext]
    public string Label { get; set; } = "";
}

[EncryptedEntity("conflict")]
internal sealed class AttributeConflictCustomer
{
    public int Id { get; set; }

    [Encrypted("value")]
    [Plaintext]
    public string Value { get; set; } = "";
}

internal sealed class FluentPoco
{
    public int Id { get; set; }
    public string Secret { get; set; } = "";
    public string Label { get; set; } = "";
}

internal abstract class InMemoryAuditContext : DbContext
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
        optionsBuilder
            .UseInMemoryDatabase("proteos-audit-" + GetType().Name)
            .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning));
}

internal sealed class AuditModelContext : InMemoryAuditContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AuditCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

internal sealed class FluentPlaintextContext : InMemoryAuditContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<FluentPoco>().IsEncryptedEntity("fluent");
        entity.Property(x => x.Secret).IsEncrypted("secret");
        entity.Property(x => x.Label).IsPlaintext();
        modelBuilder.UseProteosEncryptionModel();
    }
}

internal sealed class AttributeConflictContext : InMemoryAuditContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AttributeConflictCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

internal sealed class FluentConflictContext : InMemoryAuditContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<FluentPoco>()
            .IsEncryptedEntity("fluent")
            .Property(x => x.Secret).IsEncrypted("secret").IsPlaintext();
        modelBuilder.UseProteosEncryptionModel();
    }
}

internal sealed class StrictCustomerContext : DbContext
{
    public StrictCustomerContext(DbContextOptions<StrictCustomerContext> options)
        : base(options)
    {
    }

    public DbSet<AuditCustomer> Customers => Set<AuditCustomer>();

    public DbSet<AuditEmployee> Employees => Set<AuditEmployee>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AuditCustomer>();
        modelBuilder.Entity<AuditEmployee>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

internal sealed class StrictCleanContext : DbContext
{
    public StrictCleanContext(DbContextOptions<StrictCleanContext> options)
        : base(options)
    {
    }

    public DbSet<CleanCustomer> Customers => Set<CleanCustomer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<CleanCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

public sealed class AuditReportTests
{
    private static EncryptionAuditEntry Entry(EncryptionAuditReport report, string propertyName) =>
        report.Entries.Single(entry => entry.PropertyName == propertyName);

    [Fact]
    public void Audit_ClassifiesEveryStringAndByteArrayProperty()
    {
        using var context = new AuditModelContext();

        var report = context.GetEncryptionAuditReport();

        Assert.Equal(EncryptionClassification.EncryptedSearchable, Entry(report, "Email").Classification);
        Assert.Equal(EncryptionClassification.Encrypted, Entry(report, "Phone").Classification);
        Assert.Equal(EncryptionClassification.Encrypted, Entry(report, "Ssn").Classification);
        Assert.Equal(EncryptionClassification.Plaintext, Entry(report, "DisplayName").Classification);
        Assert.Equal(EncryptionClassification.Unclassified, Entry(report, "Notes").Classification);
    }

    [Fact]
    public void Audit_ExcludesKeysAndBlindIndexColumns()
    {
        using var context = new AuditModelContext();

        var report = context.GetEncryptionAuditReport();

        Assert.DoesNotContain(report.Entries, entry => entry.PropertyName == "Id");        // not string/byte[]
        Assert.DoesNotContain(report.Entries, entry => entry.PropertyName == "EmailIndex"); // internal shadow index
    }

    [Fact]
    public void Audit_Unclassified_ListsOnlyTheUnclassifiedProperty()
    {
        using var context = new AuditModelContext();

        var report = context.GetEncryptionAuditReport();

        Assert.Equal(new[] { "Notes" }, report.Unclassified.Select(entry => entry.PropertyName).ToArray());
    }

    [Fact]
    public void Audit_ToString_RendersAReadableTable()
    {
        using var context = new AuditModelContext();

        var text = context.GetEncryptionAuditReport().ToString();

        Assert.Contains("AuditCustomer.Email", text);
        Assert.Contains("encrypted searchable", text);
        Assert.Contains("UNCLASSIFIED", text);
    }

    [Fact]
    public void Audit_FluentPlaintextAndEncrypted_AreClassified()
    {
        using var context = new FluentPlaintextContext();

        var report = context.GetEncryptionAuditReport();

        Assert.Equal(EncryptionClassification.Encrypted, Entry(report, "Secret").Classification);
        Assert.Equal(EncryptionClassification.Plaintext, Entry(report, "Label").Classification);
    }
}

public sealed class StrictModeTests
{
    private static ServiceProvider BuildProvider<TContext>(bool strict)
        where TContext : DbContext
    {
        return new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                o.UseSingleTenant("acme");
                if (strict)
                {
                    o.EnableStrictMode();
                }
            })
            .AddDbContext<TContext>((sp, options) => options
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
                .UseProteosEncryption(sp))
            .BuildServiceProvider();
    }

    [Fact]
    public void StrictMode_UnclassifiedProperties_FailSave_AggregatingAll()
    {
        using var provider = BuildProvider<StrictCustomerContext>(strict: true);
        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<StrictCustomerContext>();
        context.Customers.Add(new AuditCustomer { Email = "a@b.com" });

        var exception = Assert.Throws<StrictModeViolationException>(() => context.SaveChanges());

        var paths = exception.Violations.Select(violation => violation.Path).ToHashSet();
        Assert.Contains("AuditCustomer.Notes", paths);
        Assert.Contains("AuditEmployee.Iban", paths); // aggregated across entities, not the first failure only
    }

    [Fact]
    public void StrictModeOff_UnclassifiedProperty_SavesNormally()
    {
        using var provider = BuildProvider<StrictCustomerContext>(strict: false);
        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<StrictCustomerContext>();
        var customer = new AuditCustomer { Email = "a@b.com" };
        context.Customers.Add(customer);

        context.SaveChanges();

        Assert.NotEqual("a@b.com", customer.Email); // encrypted, save went through
    }

    [Fact]
    public void StrictMode_FullyClassifiedModel_SavesNormally()
    {
        using var provider = BuildProvider<StrictCleanContext>(strict: true);
        using var scope = provider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<StrictCleanContext>();
        var customer = new CleanCustomer { Email = "a@b.com", Label = "label" };
        context.Customers.Add(customer);

        context.SaveChanges();

        Assert.NotEqual("a@b.com", customer.Email);
        Assert.Equal("label", customer.Label); // plaintext, untouched
    }
}

public sealed class ClassificationConflictTests
{
    [Fact]
    public void AttributeEncryptedAndPlaintext_IsHardError()
    {
        Assert.Throws<EncryptedEntityMetadataException>(() =>
        {
            using var context = new AttributeConflictContext();
            _ = context.Model;
        });
    }

    [Fact]
    public void FluentEncryptedThenPlaintext_IsHardError()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            using var context = new FluentConflictContext();
            _ = context.Model;
        });
    }
}
