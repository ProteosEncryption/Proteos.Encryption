# Fluent API

The fluent API is the attribute-free way to configure encryption. It keeps your domain model clean of
infrastructure attributes — useful for clean-architecture projects where entities live in a layer that
should not reference encryption packages.

← [Back to README](../README.md)

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<Customer>()
        .IsEncryptedEntity("customer")
        .Property(x => x.Email)
        .IsEncryptedEmail("email");

    modelBuilder.Entity<Customer>()
        .Property(x => x.Phone)
        .IsEncrypted("phone");

    modelBuilder.Entity<Customer>()
        .Property(x => x.DisplayName)
        .IsPlaintext();

    modelBuilder.UseProteosEncryptionModel(); // call LAST
}
```

## Methods

| Fluent | Attribute equivalent |
|---|---|
| `entityBuilder.IsEncryptedEntity("customer")` | `[EncryptedEntity("customer")]` |
| `propertyBuilder.IsEncrypted("phone")` | `[Encrypted("phone")]` |
| `propertyBuilder.IsEncryptedSearchable("alias", normalizer, indexProperty)` | `[EncryptedSearchable("alias", …)]` |
| `propertyBuilder.IsEncryptedEmail("email")` | `[EncryptedEmail("email")]` |
| `propertyBuilder.IsPlaintext()` | `[Plaintext]` |

It is the same surface as [attributes](attributes.md): same logical names, same shadow columns, same
auto-index, same normalizers.

## Equivalent, not second-class

Attributes and fluent resolve into the **same metadata** — neither is "just sugar". You can mix them:
attributes on one property, fluent on another, even attribute + fluent on the **same** property as long
as they agree.

## Conflicts are hard errors

If an attribute and the fluent API configure the same property with a **different** cryptographic
identity (a different logical name, searchable vs. not, a different normalizer), the model build
**fails** — it is never silently overridden:

```csharp
[Encrypted("email")]                                  // attribute says "email"
public string Email { get; set; } = "";

modelBuilder.Entity<Customer>()
    .Property(x => x.Email)
    .IsEncrypted("primary");                          // fluent says "primary" → hard error
```

Identical configuration in both places is allowed (idempotent).

## The EF model is the runtime source of truth

`UseProteosEncryptionModel()` merges attributes and fluent into one validated metadata set and stores
it on the EF Core model. At runtime the interceptors and the query helper read **only** the model —
they never know whether a field was configured by an attribute or fluently. There is no separate
metadata cache and no hidden global state.
