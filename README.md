# Proteos — Application Layer Encryption for .NET

[![CI](https://github.com/ProteosEncryption/Proteos.Encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/ProteosEncryption/Proteos.Encryption/actions/workflows/ci.yml)

Encrypt sensitive entity fields **in the application**, before they reach the database, blob
storage or any cloud system. A database, backup or storage leak then exposes only ciphertext —
not your customers' data.

Proteos plugs into Entity Framework Core: you mark which properties are sensitive, and encryption,
decryption and exact-match search happen automatically.

> **Status: Public preview (`0.1.0-preview.3`).** The cryptographic core is stable and well-tested; as a
> pre-1.0 release, some APIs may still be refined before 1.0. Ships the development key provider plus the
> Azure Key Vault, AWS KMS and Google Cloud KMS providers.
> See [Limitations](docs/limitations.md) and the [Threat model](docs/threat-model.md).

## What problem does it solve?

- **DB / backup / cloud-storage leaks** — TDE/disk encryption protect the disk, not someone who can
  *read* the database (a DBA, a cloud operator, a leaked backup, a read-only data pipeline). Proteos
  encrypts the values themselves, so reads return ciphertext without the keys.
- **Accidental plaintext** — an opt-in audit report and strict mode catch fields that aren't classified.
- **Compliance pressure** (pseudonymisation, crypto-shredding) — keys live in a KMS; destroying a key
  makes its data unrecoverable.

It is **not** end-to-end encryption and does **not** protect against a compromised application server
(see [Limitations](docs/limitations.md)).

## Packages

| Package | What it is |
|---|---|
| `Proteos.Encryption.Abstractions` | Interfaces, attributes, value objects. No dependencies. |
| `Proteos.Encryption.Core` | Crypto core: AES-256-GCM, HKDF, envelope, blind index, key providers. → Abstractions |
| `Proteos.Encryption.EntityFrameworkCore` | EF Core integration: interceptors, fluent API, query helper, migration services. → Core |
| `Proteos.Encryption.AzureKeyVault` | Azure Key Vault `IKeyProvider` adapter (RSA-OAEP-256). → Abstractions |
| `Proteos.Encryption.AwsKms` | AWS KMS `IKeyProvider` adapter (symmetric Encrypt/Decrypt). → Abstractions |
| `Proteos.Encryption.GoogleCloudKms` | Google Cloud KMS `IKeyProvider` adapter (symmetric Encrypt/Decrypt). → Abstractions |

The compile-time analyzers ship **inside** the EF Core package, so referencing it is enough to get the
warnings — no extra package to install.

```xml
<PackageReference Include="Proteos.Encryption.EntityFrameworkCore" Version="0.1.0-preview.3" />
```

## Quick start

```csharp
// 1. Register services
services.AddProteosEncryption(options =>
{
    options.UseLocalDevelopmentKeyProvider(); // DEV ONLY — never in production
    options.UseSingleTenant("demo");
});

// 2. Wire the DbContext
services.AddDbContext<AppDbContext>((sp, options) =>
{
    options.UseSqlite(connectionString);
    options.UseProteosEncryption(sp);
});
```

```csharp
public class Customer
{
    public int Id { get; set; }

    [EncryptedEmail("email")] // encrypted + searchable
    public string Email { get; set; } = "";

    [Encrypted("phone")]      // encrypted only
    public string Phone { get; set; } = "";
}

// In AppDbContext.OnModelCreating, after configuring entities:
modelBuilder.UseProteosEncryptionModel();
```

```csharp
db.Customers.Add(new Customer { Email = "max@example.com", Phone = "+49…" });
await db.SaveChangesAsync();                          // stored encrypted

var loaded = await db.Customers.FirstAsync();         // decrypted on load
loaded.Email; // "max@example.com"

var found = await db.Customers
    .WhereEncryptedEquals(db, x => x.Email, "max@example.com")  // searches a blind index
    .FirstOrDefaultAsync();
```

**Full walkthrough: [docs/getting-started.md](docs/getting-started.md).**

## Documentation

- [Getting started](docs/getting-started.md) — the complete minimal path.
- [Attributes](docs/attributes.md) — `[Encrypted]`, `[EncryptedSearchable]`, `[EncryptedEmail]`, `[Plaintext]`.
- [Fluent API](docs/fluent-api.md) — the attribute-free equivalent.
- [Querying](docs/querying.md) — searching encrypted fields, and what *not* to do.
- [Audit & strict mode](docs/audit-and-strict-mode.md) — catching unclassified fields.
- [Key rotation](docs/key-rotation.md) — multiple key versions, KMS foundation, re-encryption.
- [Limitations](docs/limitations.md) — read this before adopting.
- [Architecture specification](docs/architecture/application-layer-encryption-foundation.md) — the authoritative design.

## Samples

Three runnable samples live under [`samples/`](samples):

- **[Proteos.SampleApi](samples/Proteos.SampleApi)** — the 5-minute quickstart: a minimal Web API
  (entity, DbContext, one service + controller) showing save/load and encrypted search.
- **[Proteos.FeatureShowcase](samples/Proteos.FeatureShowcase)** — a console app with ten scenarios
  covering every feature: save/load, encrypted search, audit, strict mode, key rotation, rotation-aware
  search, the re-encryption foundation, Azure/AWS setup (examples), and the analyzer rules.
- **[Proteos.CrmSampleApi](samples/Proteos.CrmSampleApi)** — a realistic CRM Web API: multiple
  related entities, EF `Include`, `WhereEncryptedEquals` and `WhereEncryptedIn`, strict mode, and admin
  endpoints for the audit report, ciphertext-at-rest preview and re-encryption status.

## Production note

`UseLocalDevelopmentKeyProvider()` derives every key deterministically from a single root key — anyone
with that key can reproduce every key. **It is for development and tests only.** Production needs a
KMS-backed key provider (an `IKeyProvider` adapter). The Azure Key Vault, AWS KMS and Google Cloud KMS
providers ship as separate packages (`Proteos.Encryption.AzureKeyVault`, `Proteos.Encryption.AwsKms`,
`Proteos.Encryption.GoogleCloudKms`). See [Key rotation](docs/key-rotation.md).

## Security

Proteos performs application-layer encryption — it is **not** end-to-end encryption, and it has not had an
independent third-party security audit. Read the [threat model](docs/threat-model.md) to understand what
it does and does not protect.

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md). Do not open a
public issue for security reports.

## License

Apache License 2.0. See [LICENSE](LICENSE).
