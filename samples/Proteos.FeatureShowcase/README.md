# Proteos Feature Showcase

A console application that demonstrates, in one place, **what Proteos can do**. Where
[`Proteos.SampleApi`](../Proteos.SampleApi) is the 5‑minute quickstart, this is the
"what are all the features?" tour.

Each capability is a small, self-contained scenario under [`Scenarios/`](Scenarios). Run one, or run
them all, and read the code top to bottom — there is no repository layer, no CQRS, no MediatR, no
clean-architecture scaffolding. Just the feature and the few lines it takes to use it.

> ⚠️ Every scenario uses the **LocalDevelopmentKeyProvider** (a fixed in-memory key). Never use it in
> production — use Azure Key Vault or AWS KMS (scenarios 8 and 9).

## Run

```bash
cd samples/Proteos.FeatureShowcase

dotnet run            # prints the menu, then reads your choice from the console
dotnet run -- 0       # run everything
dotnet run -- 5       # run a single scenario by number
```

The SQLite database `showcase.db` is created automatically (and reset by the scenarios that need a
clean slate).

```
=========================================
Proteos Feature Showcase
=========================================

[1] Save and load
[2] Encrypted search
[3] Audit report
[4] Strict mode
[5] Key rotation
[6] Rotation-aware search
[7] ReEncrypt/ReIndex
[8] Azure Key Vault setup
[9] AWS KMS setup
[10] Analyzer examples
[0] Run everything
```

## The model

The whole tour uses one entity ([`Customer.cs`](Customer.cs)), with each attribute showing a
different classification:

```csharp
[EncryptedEntity("customer")]
public class Customer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]       // encrypted + searchable, email-normalized
    public required string Email { get; set; }

    [EncryptedSearchable("name")]   // encrypted + searchable (exact match)
    public required string Name { get; set; }

    [Encrypted("phone")]            // encrypted only — NOT searchable
    public required string Phone { get; set; }
}
```

All wiring lives in [`Infrastructure/ShowcaseHost.cs`](Infrastructure/ShowcaseHost.cs): one
`AddProteosEncryption(...)`, one `AddDbContext(... UseProteosEncryption(sp))`, and
`UseProteosEncryptionModel()` in the context. That is the entire amount of setup an application needs.

## Scenarios

### 1 — Save and load
Save a customer and load it back, writing no crypto code. Proteos encrypts on `SaveChanges` and
decrypts on materialization. Then it reads the raw column straight from SQLite to prove the database
holds ciphertext.

```
Customer saved.
Customer loaded.
Email: max@example.com

Raw database value:
  UEVOQwEBARKiJgk5A6duEevrZbcO57/j…
  decoded magic marker: "PENC"  (Proteos envelope: True)
  contains plaintext "max@example.com"? False
```

### 2 — Encrypted search
Equality search over encrypted fields with `WhereEncryptedEquals`, by email and by name.

```
Search by email "max@example.com" -> found: Max Mustermann
Search by name  "Anna Müller"      -> found: anna@example.com
```

A normal LINQ comparison is **wrong** on an encrypted column:

```csharp
// WRONG:
// db.Customers.Where(x => x.Email == email)
```

The column stores random-nonce ciphertext, so a plaintext `==` never matches. `WhereEncryptedEquals`
hashes the term into the blind index and compares *that* in SQL.

### 3 — Audit report
`db.GetEncryptionAuditReport()` classifies every string/`byte[]` property — derived from the EF model,
no database access.

```
Property             Classification
------------------------------------------
Customer.Email       EncryptedSearchable
Customer.Name        EncryptedSearchable
Customer.Phone       Encrypted
```

(A property marked `[Plaintext]` would show as `Plaintext`; an unclassified one as `Unclassified`.)

### 4 — Strict mode
Explains `options.EnableStrictMode()` and shows that the fully-classified `Customer` passes it — no
exception is provoked. With strict mode on, an *unclassified* property fails the save with one
aggregated error.

```
Unclassified properties on Customer: 0.
Saved successfully under strict mode (every property is classified).
```

### 5 — Key rotation
Save Customer A under key version 1, switch the current key to v2, save Customer B, then read both.
The provider still holds v1, so the older row stays decryptable.

```
Customer A -> v1
Customer B -> v2
Both decrypted successfully: Customer A (a@example.com), Customer B (b@example.com)
```

### 6 — Rotation-aware search
Two customers share a name but were saved under different key versions (so their blind indexes
differ). The search recomputes the term's index under every known key version, so one query finds
both.

```
Search returned 2 customers.
```

### 7 — ReEncrypt / ReIndex
After rotation, `IEncryptionMigrationPlanner` detects which stored values are under an older key — by
reading the envelope **header** only, no decryption. The full migration is described, not performed.

```
Stored under key id : D4ABE619CCF50BF47DA420E01C44B88C0001
Current key id      : 924C590553103221173D589CD6109B910002
NeedsReEncryption    : True
```

(Note the trailing `0001` vs `0002`: the key id carries the version.)

### 8 — Azure Key Vault setup (example only)
Shows the real registration call — no credentials, nothing is executed.

```csharp
services.AddProteosAzureKeyVault(options =>
{
    options.KeyIdentifier = new Uri("https://my-vault.vault.azure.net/keys/proteos-kek/abcdef0123");
    // options.Credential defaults to DefaultAzureCredential when omitted.
});
```

### 9 — AWS KMS setup (example only)
The AWS equivalent — no secrets, nothing is executed.

```csharp
services.AddProteosAwsKms(options =>
{
    options.KeyId = "arn:aws:kms:eu-central-1:111122223333:key/abcd1234-...";
    options.Region = "eu-central-1"; // optional when the key reference is an ARN
});
```

### 10 — Analyzer examples
The Roslyn analyzer that ships with the EF package flags encrypted-property misuse at compile time
(examples kept as comments so the project compiles cleanly):

```csharp
// PENC001 — projecting an encrypted property returns ciphertext:
db.Customers.Select(x => x.Email);

// PENC002 — comparing an encrypted property with == never matches:
db.Customers.Where(x => x.Email == email);

// Correct:
db.Customers.WhereEncryptedEquals(db, x => x.Email, email);
```

## Project layout

```
Proteos.FeatureShowcase/
├── Customer.cs                  // the demo entity
├── ShowcaseDbContext.cs         // UseProteosEncryptionModel()
├── Program.cs                   // menu + runner
├── Infrastructure/
│   ├── IScenario.cs             // Title + ExecuteAsync()
│   ├── ShowcaseHost.cs          // the entire DI wiring, in one place
│   └── RawDatabaseInspector.cs  // raw SQLite read (proves ciphertext at rest)
└── Scenarios/
    └── Scenario01..10*.cs       // one feature each
```
