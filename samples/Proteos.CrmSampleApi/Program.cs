using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi;
using Proteos.CrmSampleApi.Data;
using Proteos.CrmSampleApi.Services.Admin;
using Proteos.CrmSampleApi.Services.Contacts;
using Proteos.CrmSampleApi.Services.Customers;
using Proteos.CrmSampleApi.Services.Orders;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//
// Proteos Encryption
//
// This sample intentionally uses the LocalDevelopmentKeyProvider so it can run
// immediately without any cloud credentials.
//
// Proteos also supports production setups with Azure Key Vault and AWS KMS.
// In those scenarios the key provider is supplied through UseKeyProvider(...)
// together with a RegistryKeyMaterialProvider.
//
// The important part:
//
// Your DbContext, entities, services and controllers do NOT change.
// Only the key provider configuration changes.
//
builder.Services.AddProteosEncryption(options =>
{
    // Development only.
    // Never use this provider in production.
    options.UseLocalDevelopmentKeyProvider();

    // Single-tenant sample setup.
    options.UseSingleTenant(CrmConstants.Tenant);

    // Require every string and byte[] property to be explicitly classified
    // with [Encrypted], [EncryptedSearchable], [EncryptedEmail] or [Plaintext].
    options.EnableStrictMode();

    /*
    -------------------------------------------------------------------------
    Example production setup (simplified)

    options.UseKeyProvider(sp =>
    {
        var registry = sp.GetRequiredService<ITenantKeyRegistry>();

        return new RegistryKeyMaterialProvider(
            registry,
            new Dictionary<KeyProviderKind, IKeyProvider>
            {
                [KeyProviderKind.AzureKeyVault] =
                    sp.GetRequiredService<AzureKeyVaultKeyProvider>()

                // or:

                [KeyProviderKind.AwsKms] =
                    sp.GetRequiredService<AwsKmsKeyProvider>()
            });
    });

    -------------------------------------------------------------------------

    The rest of the application stays exactly the same.
    */
});

// DbContext (SQLite).
//
// The (sp, options) overload is required so the Proteos interceptors and the
// tenant resolution run inside the current request scope.
builder.Services.AddDbContext<CrmSampleDbContext>((serviceProvider, options) =>
{
    options.UseSqlite(CrmConstants.ConnectionString);

    // Enables automatic encryption on SaveChanges and automatic decryption
    // during entity materialization.
    options.UseProteosEncryption(serviceProvider);
});

// Application services.
builder.Services.AddScoped<ICustomerService, CustomerService>();
builder.Services.AddScoped<IContactService, ContactService>();
builder.Services.AddScoped<IOrderService, OrderService>();
builder.Services.AddScoped<IAdminService, AdminService>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

// Create the database and seed demo data on first run.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<CrmSampleDbContext>();

    db.Database.EnsureCreated();

    await SeedData.SeedAsync(db);
}

app.MapControllers();

app.Run();