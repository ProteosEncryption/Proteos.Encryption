# Getting started

This is the complete minimal path to encrypting a field, saving it, loading it and searching for it.

← [Back to README](../README.md)

## 1. Install

```xml
<PackageReference Include="Proteos.Encryption.EntityFrameworkCore" Version="0.1.0-preview.1" />
```

`Core`, `Abstractions` and the analyzers come transitively — you only reference the EF Core package.

## 2. Configure services

```csharp
services.AddProteosEncryption(options =>
{
    options.UseLocalDevelopmentKeyProvider(); // DEV ONLY — never in production
    options.UseSingleTenant("demo");
});
```

- `UseLocalDevelopmentKeyProvider()` is deterministic and insecure — for development and tests only.
- `UseSingleTenant("demo")` pins one tenant. For multi-tenant apps use
  `UseTenant(sp => sp.GetRequiredService<ITenantContext>().TenantId)` — the tenant is resolved per
  operation and is the unit of key isolation (a tenant = an organisation, not an end user).
- A missing key provider or tenant resolver fails at startup, not at the first save.

## 3. Wire the DbContext

```csharp
services.AddDbContext<AppDbContext>((sp, options) =>
{
    options.UseSqlite(connectionString);
    options.UseProteosEncryption(sp); // adds the encrypt/decrypt interceptors
});
```

Use the `(sp, options) => …` overload so the encryption services resolve from the request scope.

## 4. Configure the model

```csharp
public class AppDbContext : DbContext
{
    public DbSet<Customer> Customers => Set<Customer>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Either attributes on the entity, or the fluent API shown here — they are equivalent.
        modelBuilder.Entity<Customer>()
            .IsEncryptedEntity("customer")
            .Property(x => x.Email)
            .IsEncryptedEmail("email");

        modelBuilder.UseProteosEncryptionModel(); // call LAST, after all entities are configured
    }
}
```

`UseProteosEncryptionModel()` builds the encryption metadata and creates the blind-index shadow
columns. Forgetting it makes a save fail loudly rather than storing plaintext silently.

## 5. The entity

```csharp
public class Customer
{
    public int Id { get; set; }

    public string Email { get; set; } = "";   // configured as encrypted+searchable above

    [Encrypted("phone")]                       // attributes and fluent can be mixed
    public string Phone { get; set; } = "";

    public string DisplayName { get; set; } = ""; // a normal, plaintext property
}
```

See [Attributes](attributes.md) and [Fluent API](fluent-api.md) for all the options.

## 6. Save

```csharp
db.Customers.Add(new Customer { Email = "max@example.com", Phone = "+49 30 12345", DisplayName = "Max" });
await db.SaveChangesAsync();
```

On save, `Email` and `Phone` are encrypted; `Email`'s blind index is computed; `DisplayName` is stored
as-is. The database column holds a ciphertext envelope, never the plaintext.

## 7. Load

```csharp
var customer = await db.Customers.FirstAsync();
customer.Email; // "max@example.com" — decrypted automatically on materialization
```

Decryption happens only when a **full entity** is materialized (see [Querying](querying.md) for the
projection caveat).

## 8. Search

```csharp
var match = await db.Customers
    .WhereEncryptedEquals(db, x => x.Email, "max@example.com")
    .FirstOrDefaultAsync();
```

`WhereEncryptedEquals` computes the blind index of the search term and filters the internal index
column. The database never sees the plaintext. Only exact-match search is supported — see
[Querying](querying.md).

## Next

- [Audit & strict mode](audit-and-strict-mode.md) — make sure no sensitive field is left unclassified.
- [Key rotation](key-rotation.md) — what happens when keys rotate.
- [Limitations](limitations.md) — read before adopting.
