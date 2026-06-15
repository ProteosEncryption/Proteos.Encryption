# Key rotation & key management

Keys can be rotated without re-encrypting existing data up front: new data uses the current key, old
data stays readable and searchable. This page explains how, and the foundations that production key
management builds on.

← [Back to README](../README.md)

## How rotation works

- **Encryption always uses the current key** (`GetCurrentKeyId(tenant)`). New writes are stamped with
  the current key version.
- **Decryption uses the key id stored in the envelope header.** Every ciphertext carries its
  `KeyId = TmkId ‖ Version`, so a value written under an older version decrypts with that version —
  no special cases, no `if (version == n)`.
- **The envelope format never changes** to support rotation — the key id in the header is enough.
- **Old data stays readable.** Rotating just adds a new version and moves the "current" pointer; old
  versions remain resolvable.

### Search across versions

Because older rows have blind indexes from older key versions, search computes the term under **all
known key versions** (`GetKnownKeyIds(tenant)` → `ComputeForAllKnownKeys`) and ORs them. See
[Querying](querying.md). Each extra version adds an `OR` term; re-encryption (below) brings that back down.

## Re-encrypt / re-index (foundation)

To migrate old data onto the current key, Proteos provides the building blocks (no background worker
yet — that orchestration is later):

- `IEncryptionMigrationPlanner` — detects, by **reading the envelope header only** (no decryption),
  which stored values are under an older key version (`Header.KeyId != current`). `null` needs no
  migration; an invalid envelope is an error.
- `IEncryptionMigrationService` — re-encrypts a value: **decrypt under the old key, encrypt under the
  current key**, and for searchable properties **recompute the blind index** with the current index
  key. (A blind index can only be derived from plaintext, so this is decrypt + encrypt + reindex, not
  an in-place header rewrite.)

These operate on stored raw values, so a worker reads/writes raw rows without the interceptors
double-processing them.

**Batch / progress / resume value objects.** To shape a future batch worker (which is *not* built
yet), the foundation also provides immutable value objects — they execute nothing and persist nothing:

- `ReEncryptBatchOptions` — the batch size.
- `ReEncryptBatchResult` — one batch's outcome: re-encrypted / skipped / failed counts, the next
  resume token and whether more batches remain.
- `ReEncryptProgress` — cumulative progress across batches; `AfterBatch(result)` folds a batch in and
  flips `IsComplete` when no more remain.
- `ReEncryptResumeToken` — an opaque, worker-defined cursor (for example the last processed primary
  key) to continue from; `Beginning` starts a fresh run.

A worker would loop: `progress = progress.AfterBatch(RunBatch(options, progress.Resume))` until
`progress.IsComplete`. The `RunBatch` step — the actual database read/write — is the worker's job and
is intentionally out of scope here.

## Production key management (foundation)

Two clean layers keep cloud providers thin:

- **`IKeyProvider` — the KEK seam.** Wraps and unwraps the Tenant Master Key. A cloud adapter (Azure
  Key Vault, AWS KMS, Google KMS, HashiCorp Vault) implements only this — no derivation, no EF.
- **`IKeyMaterialProvider` — derivation.** `Tenant + KeyId + Scope + Purpose → AES/HMAC working key`
  via HKDF. Vendor-neutral.

A neutral, storage-agnostic catalogue describes a tenant's keys (no database is forced):

```text
Tenant A
 ├── TmkId  (stable, 16-byte id)
 ├── Version 1 → ProviderKeyReference + WrappedTenantMasterKey
 ├── Version 2 → ProviderKeyReference + WrappedTenantMasterKey
 └── CurrentVersion = 2
```

`TenantKeyRecord`, `TenantKeyVersion`, `ProviderKeyReference`, `KeyProviderKind` and
`ITenantKeyRegistry` model this. **`RegistryKeyMaterialProvider`** wires it together: it fetches the
record from the registry, resolves the key id to a version, unwraps the TMK through the matching
`IKeyProvider`, derives the working key with HKDF, and zeroes the TMK afterwards.

## Cloud key providers (Azure Key Vault, AWS KMS)

Two KEK adapters ship as separate packages. Each implements only the `IKeyProvider` KEK seam —
wrapping and unwrapping the tenant master key — and does no derivation, no EF and no tenant
resolution:

- **`Proteos.Encryption.AzureKeyVault`** wraps/unwraps with an Azure Key Vault key using
  **RSA-OAEP-256**. Register it with
  `AddProteosAzureKeyVault(o => o.KeyIdentifier = new Uri("https://my-vault.vault.azure.net/keys/proteos-kek/<version>"))`;
  the credential defaults to `DefaultAzureCredential` when not set.
- **`Proteos.Encryption.AwsKms`** wraps/unwraps with an AWS KMS symmetric CMK (**`Encrypt`/`Decrypt`**,
  `SYMMETRIC_DEFAULT`; the CMK never leaves KMS). Register it with
  `AddProteosAwsKms(o => { o.KeyId = "arn:aws:kms:<region>:<account>:key/<id>"; o.Region = "<region>"; })`;
  credentials come from the AWS SDK default chain.

Each `AddProteos…` call registers only the adapter (the concrete `…KeyProvider`). The application
still wires it into a `RegistryKeyMaterialProvider` (via `UseKeyProvider(...)`) as the provider for its
`KeyProviderKind` — that wiring stays in the application, so these packages depend on nothing beyond
`Abstractions`.

## What is not here yet

- **No Google Cloud KMS adapter.** The Azure Key Vault and AWS KMS adapters ship (see above); a Google
  KMS adapter is still open.
- **No re-encryption worker.** The planner and service exist; the batch runner / orchestration do not.
- **`LocalDevelopmentKeyProvider` is development-only** and insecure — never use it in production.
