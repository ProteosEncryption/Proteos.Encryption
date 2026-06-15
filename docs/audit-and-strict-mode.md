# Audit report & strict mode

A property that should be encrypted but is left unclassified would be stored as plaintext, silently.
The audit report and strict mode exist to catch that.

← [Back to README](../README.md)

## Audit report

Ask any context for a classification of every `string` / `byte[]` property in its model:

```csharp
var report = dbContext.GetEncryptionAuditReport();

Console.WriteLine(report);          // a readable table
report.Entries;                     // every audited property + its classification
report.Unclassified;                // the ones that are neither encrypted nor plaintext
```

`ToString()` produces, for example:

```text
Customer.Email      encrypted searchable
Customer.Phone      encrypted
Customer.Ssn        encrypted
Customer.Name       plaintext
Customer.Notes      UNCLASSIFIED
```

| Classification | Meaning |
|---|---|
| `encrypted` | `[Encrypted]` / `.IsEncrypted(...)` |
| `encrypted searchable` | `[EncryptedSearchable]` / `[EncryptedEmail]` |
| `plaintext` | `[Plaintext]` / `.IsPlaintext()` — a deliberate choice |
| `unclassified` | neither — a candidate for accidental plaintext |

Primary keys, non-string/`byte[]` types and the internal blind-index columns are not audited. The
report is derived purely from the model — no decryption, no DI required. Use it programmatically (for
example to fail a startup health check) or just log it.

## Strict mode

Strict mode makes "unclassified" a hard failure. Opt in at registration:

```csharp
services.AddProteosEncryption(options =>
{
    options.UseLocalDevelopmentKeyProvider();
    options.UseSingleTenant("demo");
    options.EnableStrictMode();
});
```

With strict mode on, **every** `string` / `byte[]` property must be classified as encrypted,
encrypted-searchable or `[Plaintext]`. There are **no name heuristics, no blacklists and no silent
defaults** — you classify everything explicitly, or the save fails.

### Enforced at the save boundary

Strict mode is enforced when data is **written** — the exact moment accidental plaintext would be
persisted — not at model build (the model convention has no access to the DI option). Consequences:

- A read-only context never triggers it (it writes nothing, so it can't leak plaintext). To check at
  startup regardless, evaluate the audit report yourself:
  `if (db.GetEncryptionAuditReport().Unclassified.Count > 0) throw …`.
- The shipped analyzers (`PENC001`/`PENC002`) catch projection and `==` footguns at compile time; a
  compile-time **classification** check (catching unclassified properties) is reserved for a future
  analyzer rule. Strict mode is the runtime guard for classification today.

### Aggregated errors

Strict mode does not stop at the first problem — it reports **all** unclassified properties together:

```text
Proteos strict mode: the following string/byte[] properties are not classified …
  Customer.Notes
  Employee.Iban
  Company.Logo
```

### Technical byte[] columns

Strict mode considers **every** `string` / `byte[]` property, including technical ones such as a
`[Timestamp]`/RowVersion concurrency token. Those must be classified explicitly too — mark them
`[Plaintext]` (or `.IsPlaintext()`).
