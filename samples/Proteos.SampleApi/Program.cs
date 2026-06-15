using Microsoft.EntityFrameworkCore;
using Proteos.SampleApi;
using Proteos.SampleApi.Services;

var builder = WebApplication.CreateBuilder(args);

// The API surface lives in controllers (see Controllers/CustomersController.cs).
builder.Services.AddControllers();

// 1) Register Proteos encryption.
//    Development only. Use Azure Key Vault or AWS KMS in production.
builder.Services.AddProteosEncryption(options =>
{
    // The development key provider keeps a fixed key in memory. Never use it in production.
    options.UseLocalDevelopmentKeyProvider();

    // Single-tenant deployment: every row is encrypted under the same tenant id.
    options.UseSingleTenant("sample");
});

// 2) Register the DbContext. The (sp, options) overload is required: it lets the encryption
//    interceptors and the per-operation tenant run inside the request scope.
builder.Services.AddDbContext<SampleDbContext>((sp, options) => options
    .UseSqlite("Data Source=sample.db")
    .UseProteosEncryption(sp));

// 3) Register the application service the controller depends on.
builder.Services.AddScoped<ICustomerService, CustomerService>();

var app = builder.Build();

// Create the SQLite database (including the hidden blind-index columns) and seed a few customers the
// first time the app runs, so the list and search endpoints have data to return. Only seeds when the
// table is empty.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
    db.Database.EnsureCreated();

    if (!db.Customers.Any())
    {
        db.Customers.AddRange(
            new Customer { Email = "max@example.com", Name = "Max Mustermann", Phone = "+49 123456" },
            new Customer { Email = "anna@example.com", Name = "Anna Müller", Phone = "+49 234567" },
            new Customer { Email = "john@example.com", Name = "John Smith", Phone = "+49 345678" });
        db.SaveChanges();
    }
}

app.MapControllers();

app.Run();
