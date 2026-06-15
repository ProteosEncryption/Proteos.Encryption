using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Xunit;

namespace Proteos.Encryption.EntityFrameworkCore.Tests.Interceptors;

internal sealed class EncryptingContext : DbContext
{
    private readonly EncryptingSaveChangesInterceptor _interceptor;
    private readonly string _databaseName;

    public EncryptingContext(EncryptingSaveChangesInterceptor interceptor, string databaseName)
    {
        _interceptor = interceptor;
        _databaseName = databaseName;
    }

    public DbSet<ValidCustomer> Customers => Set<ValidCustomer>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) =>
        optionsBuilder
            .UseInMemoryDatabase(_databaseName)
            .ConfigureWarnings(w => w.Ignore(CoreEventId.ManyServiceProvidersCreatedWarning))
            .AddInterceptors(_interceptor);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ValidCustomer>();
        modelBuilder.UseProteosEncryptionModel();
    }
}

public sealed class EncryptingSaveChangesInterceptorTests
{
    private static (ServiceProvider Provider, EncryptingContext Context) Setup(Action<ProteosEncryptionOptions>? configureTenant = null)
    {
        Action<ProteosEncryptionOptions> tenant = configureTenant ?? (o => o.UseSingleTenant("acme"));
        var provider = new ServiceCollection()
            .AddProteosEncryption(o =>
            {
                o.UseLocalDevelopmentKeyProvider();
                tenant(o);
            })
            .BuildServiceProvider();

        var interceptor = provider.CreateScope().ServiceProvider.GetRequiredService<EncryptingSaveChangesInterceptor>();
        return (provider, new EncryptingContext(interceptor, Guid.NewGuid().ToString()));
    }

    private static EncryptionContext Context(string entityLogical, string propertyLogical) =>
        new(new TenantId("acme"), new EncryptedDataScope(new LogicalName(entityLogical), new LogicalName(propertyLogical)));

    private static string DecryptString(ServiceProvider provider, string? stored, string entityLogical, string propertyLogical)
    {
        var service = provider.GetRequiredService<AesGcmValueEncryptionService>();
        var bytes = service.DecryptFromBytes(Convert.FromBase64String(stored!), Context(entityLogical, propertyLogical));
        return Encoding.UTF8.GetString(bytes);
    }

    [Fact]
    public void Added_EncryptsStringProperties_AndSetsBlindIndex()
    {
        var (provider, context) = Setup();
        var customer = new ValidCustomer { Email = "max@example.com", Phone = "+1-555-0100", Ssn = [1, 2, 3], PlainName = "Max" };
        context.Add(customer);

        context.SaveChanges();

        Assert.NotEqual("max@example.com", customer.Email);
        Assert.Equal("max@example.com", DecryptString(provider, customer.Email, "customer", "email"));
        Assert.Equal("+1-555-0100", DecryptString(provider, customer.Phone, "customer", "phone"));
        Assert.Equal("Max", customer.PlainName);

        var blindIndexProvider = provider.GetRequiredService<IBlindIndexProvider>();
        var expectedIndex = blindIndexProvider
            .Compute(Encoding.UTF8.GetBytes(EmailBlindIndexNormalizer.Instance.Normalize("max@example.com")), BlindIndexDescriptor.ExactMatch, Context("customer", "email"))
            .ToArray();
        var storedIndex = (byte[]?)context.Entry(customer).Property("EmailIndex").CurrentValue;
        Assert.Equal(expectedIndex, storedIndex);
        Assert.Equal(32, storedIndex!.Length);
    }

    [Fact]
    public void Added_EncryptsByteArrayProperty()
    {
        var (provider, context) = Setup();
        var customer = new ValidCustomer { Email = "a@b.com", Ssn = [9, 8, 7, 6] };
        context.Add(customer);

        context.SaveChanges();

        Assert.NotEqual(new byte[] { 9, 8, 7, 6 }, customer.Ssn);
        var service = provider.GetRequiredService<AesGcmValueEncryptionService>();
        Assert.Equal(new byte[] { 9, 8, 7, 6 }, service.DecryptFromBytes(customer.Ssn, Context("customer", "ssn")));
    }

    [Fact]
    public void NullValue_StaysNull_AndIndexIsNull()
    {
        var (_, context) = Setup();
        var customer = new ValidCustomer { Email = null!, Phone = "x" };
        context.Add(customer);

        context.SaveChanges();

        Assert.Null(customer.Email);
        Assert.Null(context.Entry(customer).Property("EmailIndex").CurrentValue);
    }

    [Fact]
    public void EmptyString_IsEncrypted()
    {
        var (provider, context) = Setup();
        var customer = new ValidCustomer { Email = "" };
        context.Add(customer);

        context.SaveChanges();

        Assert.NotEqual("", customer.Email);
        Assert.Equal("", DecryptString(provider, customer.Email, "customer", "email"));
    }

    [Fact]
    public void DoubleSave_DoesNotDoubleEncrypt()
    {
        var (provider, context) = Setup();
        var customer = new ValidCustomer { Email = "max@example.com" };
        context.Add(customer);
        context.SaveChanges();
        var afterFirstSave = customer.Email;

        context.SaveChanges();

        Assert.Equal(afterFirstSave, customer.Email);
        Assert.Equal("max@example.com", DecryptString(provider, customer.Email, "customer", "email"));
    }

    [Fact]
    public void Modified_OnlyChangedPropertiesAreReprocessed()
    {
        var (provider, context) = Setup();
        var customer = new ValidCustomer { Email = "max@example.com", Phone = "old" };
        context.Add(customer);
        context.SaveChanges();
        var encryptedEmail = customer.Email;

        customer.Phone = "new";
        context.SaveChanges();

        Assert.Equal(encryptedEmail, customer.Email); // email untouched, not re-encrypted
        Assert.Equal("new", DecryptString(provider, customer.Phone, "customer", "phone"));
    }

    [Fact]
    public void MultipleEntities_AreAllEncrypted()
    {
        var (provider, context) = Setup();
        var a = new ValidCustomer { Email = "a@b.com" };
        var b = new ValidCustomer { Email = "c@d.com" };
        context.AddRange(a, b);

        context.SaveChanges();

        Assert.Equal("a@b.com", DecryptString(provider, a.Email, "customer", "email"));
        Assert.Equal("c@d.com", DecryptString(provider, b.Email, "customer", "email"));
        Assert.NotEqual(a.Email, b.Email);
    }

    [Fact]
    public void EncryptedOnlyProperty_HasNoBlindIndexColumn()
    {
        var (_, context) = Setup();

        Assert.Null(context.Model.FindEntityType(typeof(ValidCustomer))!.FindProperty("PhoneIndex"));
    }

    [Fact]
    public void MissingTenant_AbortsSaveChanges()
    {
        var (_, context) = Setup(o => o.UseTenant(_ => (TenantId?)null));
        context.Add(new ValidCustomer { Email = "max@example.com" });

        Assert.Throws<ProteosEncryptionException>(() => context.SaveChanges());
    }

    [Fact]
    public void AlreadyEncryptedString_IsRejected_NotDoubleEncrypted()
    {
        var (provider, context) = Setup();
        var service = provider.GetRequiredService<AesGcmValueEncryptionService>();
        var ciphertext = Convert.ToBase64String(
            service.EncryptToBytes(Encoding.UTF8.GetBytes("max@example.com"), Context("customer", "email")));
        context.Add(new ValidCustomer { Email = ciphertext });

        var exception = Assert.Throws<AlreadyEncryptedValueException>(() => context.SaveChanges());

        Assert.Equal(typeof(ValidCustomer), exception.EntityType);
        Assert.Equal(nameof(ValidCustomer.Email), exception.PropertyName);
    }

    [Fact]
    public void AlreadyEncryptedByteArray_IsRejected_NotDoubleEncrypted()
    {
        var (provider, context) = Setup();
        var service = provider.GetRequiredService<AesGcmValueEncryptionService>();
        var ciphertext = service.EncryptToBytes(new byte[] { 1, 2, 3, 4 }, Context("customer", "ssn"));
        context.Add(new ValidCustomer { Email = "a@b.com", Ssn = ciphertext });

        var exception = Assert.Throws<AlreadyEncryptedValueException>(() => context.SaveChanges());

        Assert.Equal(nameof(ValidCustomer.Ssn), exception.PropertyName);
    }

    [Fact]
    public void PlaintextThatHappensToBeValidBase64_IsEncrypted_NotMisdetected()
    {
        // "dGVzdA==" is valid Base64 (decodes to "test", 4 bytes) but not a PENC envelope. A genuine
        // plaintext must never be misread as ciphertext, so this must encrypt and round-trip cleanly.
        var (provider, context) = Setup();
        var customer = new ValidCustomer { Email = "dGVzdA==" };
        context.Add(customer);

        context.SaveChanges();

        Assert.Equal("dGVzdA==", DecryptString(provider, customer.Email, "customer", "email"));
    }
}
