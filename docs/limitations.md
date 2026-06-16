# Limitations

Read this before adopting. Encrypting field values has real, unavoidable trade-offs, and this is a
foundation release — some pieces are deliberately not built yet.

← [Back to README](../README.md)

## Search

Encrypted columns hold random ciphertext, so the database cannot reason about their values. Only
**exact-match** search via a blind index is supported (see [Querying](querying.md)). Not supported:

- **`Contains` / `LIKE` / substring** search.
- **Full-text** search.
- **Range queries** (`>`, `<`, `BETWEEN`) on encrypted fields.
- **`ORDER BY`** on encrypted fields.
- **`GROUP BY` / `SUM` / aggregation** on encrypted fields.
- **`UNIQUE` constraints / foreign keys** on encrypted columns.

Token / partial-match search is a possible future module, not part of this release.

## EF Core behaviour

- **Projections can return ciphertext.** `Select(x => x.Email)` on an encrypted property bypasses the
  decryption interceptor and yields the stored ciphertext. Materialize the full entity instead.
- **Comparing with `==` in a query never matches.** Use `WhereEncryptedEquals`.
- **Raw SQL writes, `ExecuteUpdate` / `ExecuteDelete` and bulk extensions** bypass the interceptors, so
  they neither encrypt on write nor decrypt on read. Not supported.

## Analyzer

- The analyzers (`PENC001`/`PENC002`) recognise both **attribute-based** configuration and the
  **simple fluent form** (`.Property(x => x.Email).IsEncrypted(...)` / `.IsEncryptedSearchable(...)` /
  `.IsEncryptedEmail(...)`), on **direct** member access (`x => x.Email`) only — not `new { x.Email }`,
  method calls or navigation chains.
- Fluent recognition is limited to the **directly chained** form; a property builder stored in a local
  variable first is not seen. There are **no code fixes** yet.
- They are scoped to `IQueryable` (database) queries — in-memory `IEnumerable` projections are fine.

## Key management

- **`LocalDevelopmentKeyProvider` is not production-grade.** It derives all keys deterministically from
  one root key; anyone with that key reproduces every key. Development and tests only.
- **Azure Key Vault, AWS KMS and Google Cloud KMS ship.** The KMS foundation (registry model,
  `RegistryKeyMaterialProvider`, the `IKeyProvider` KEK seam) is in place, and the
  `Proteos.Encryption.AzureKeyVault` (RSA-OAEP-256), `Proteos.Encryption.AwsKms` (symmetric KMS
  `Encrypt`/`Decrypt`) and `Proteos.Encryption.GoogleCloudKms` (symmetric Cloud KMS `Encrypt`/`Decrypt`)
  adapters are shipped. Each adapter only wraps/unwraps the tenant master key; wiring it into
  `RegistryKeyMaterialProvider` stays in the application's own configuration. See [Key rotation](key-rotation.md).
- **No re-encryption worker yet** — only the planner/service plus the batch/progress/resume value
  objects (`ReEncryptBatchOptions`, `ReEncryptBatchResult`, `ReEncryptProgress`, `ReEncryptResumeToken`).
  These are foundation only: they execute nothing and persist nothing.

## Threat model

Proteos protects against *reads* of the stored data (leaked DB / backup / cloud storage, curious DBA or
cloud operator without KMS access, read-only data pipelines). It does **not** protect against:

- a **compromised application server** (RCE) — derived keys are in memory and the KMS is reachable;
- process memory dumps; compromised clients; stolen app credentials with KMS access;
- active database manipulation (replay/delete/reorder — integrity is per-value, not database-wide).

It is **not** end-to-end encryption and is a building block, not a compliance certificate. See the
[architecture specification](architecture/application-layer-encryption-foundation.md) for the full
threat model.

## Status

Public preview (`0.1.0-preview.3`). Three sample projects ship under
`samples/` — a quickstart Web API, a feature showcase console app, and a realistic CRM Web API. The README
is wired into the package, and CI (build/test) plus a pack/release workflow are in place. APIs are stable
and tested.
