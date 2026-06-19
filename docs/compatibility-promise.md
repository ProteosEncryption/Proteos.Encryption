# Compatibility Promise

This document states what Proteos.Encryption commits to keeping stable from `1.0.0` onward, what is
shipped but deliberately not yet frozen, and where breaking changes are still allowed before `1.0`. It
exists so that the boundary between "you can rely on this" and "this may still move" is explicit rather
than implied.

Two kinds of compatibility are tracked separately, because they fail very differently:

- **Data compatibility** — the on-disk/at-rest formats. Breaking one of these makes already-stored data
  undecryptable or unsearchable. There is no recompile that fixes it; only a data migration. These are
  guarded hardest.
- **API compatibility** — the public types and members. Breaking one of these forces consumers to
  recompile or adjust code, but stored data is unaffected.

← [Back to README](../README.md) · See also [Threat model](threat-model.md),
[Limitations](limitations.md).

## Stable Commitments

From `1.0.0`, the following are covered by the promise. Within a major version they will not change in a
way that breaks stored data or removes/alters public surface.

**Data formats (see [Data Compatibility](#data-compatibility) for the exact specification):**

- The version 1 ciphertext envelope binary layout.
- The header-bound AAD composition.
- The closed crypto-suite registry, including the reserved ids.
- The production KeyId scheme.
- The working-key derivation (HKDF-SHA256 with its `info` construction).
- The blind-index construction.
- The Default and Email normalizer rules.

**Public API:**

- Core abstractions: `IKeyProvider`, `IKeyMaterialProvider`, `IValueEncryptor`, `IValueDecryptor`,
  `IValueEncryptionService`, `ICiphertextEnvelopeCodec`, `IBlindIndexProvider`, `IBlindIndexNormalizer`.
- Core value types: `KeyId`, `TenantId`, `LogicalName`, `EncryptedDataScope`, `EncryptionContext`,
  `KeyDescriptor`, `CiphertextEnvelope`, `CiphertextEnvelopeHeader`, and the envelope id types
  (`EnvelopeVersion`, `CryptoSuiteId`, `AadSchemeId`).
- Entity Framework Core integration: the attributes (`[Encrypted]`, `[EncryptedSearchable]`,
  `[EncryptedEmail]`, `[Plaintext]`, `[EncryptedEntity]`), the fluent configuration API, the query
  helpers (`WhereEncryptedEquals`, `WhereEncryptedIn`, `WhereEncryptedEmail`), the registration entry
  points (`AddProteosEncryption`, `UseProteosEncryption`, `UseProteosEncryptionModel`), and the audit
  report / strict mode surface.
- Analyzer diagnostic identifiers `PENC001` and `PENC002` and their meaning. `PENC003` stays reserved.

Stability is interpreted per [Semantic Versioning](https://semver.org/): additive, backward-compatible
changes (new types, new optional members, new analyzer rules) may appear in minor releases; anything that
breaks the items above waits for the next major release.

## Preview Features

These ship today but are **not** covered by the promise. Their public surface and configuration may
change in a minor release without a major bump.

- **Cloud KMS providers** — `Proteos.Encryption.AzureKeyVault`, `Proteos.Encryption.AwsKms`,
  `Proteos.Encryption.GoogleCloudKms`. The adapter types, options and registration ergonomics are
  preview. Note the distinction: the *data* produced through a KMS provider remains readable — a KeyId is
  a frozen format, and a wrapped tenant master key is the KMS vendor's own ciphertext — so what is preview
  is the provider **API and configuration**, not the durability of data already written.
- **Re-encryption foundation** — `IEncryptionMigrationPlanner`, `IEncryptionMigrationService`, and the
  `ReEncrypt*` value objects. These are a foundation without a runnable worker or a defined transaction
  contract; their shapes may change.
- **Reserved, not active** — the reserved crypto suites (`AES-256-GCM-SIV`, `XChaCha20-Poly1305`,
  `AES-256-SIV`) and the reserved `ContextBound` AAD scheme. They occupy ids so those ids can never be
  repurposed, but they are not implemented and carry no behavioural promise yet.
- **Tenant key-catalogue types (stabilizing)** — `ITenantKeyRegistry`, `TenantKeyRecord`,
  `TenantKeyVersion`, `ProviderKeyReference`, `KeyProviderKind` and `WrappedKey`. These exist and are
  usable, but their **type signatures are not yet frozen**. They are the least-exercised surface (there is
  no end-to-end production sample yet) and they pair with the preview KMS providers, so they are expected
  to settle alongside production KMS guidance — for instance, `ITenantKeyRegistry.GetRecord` is synchronous
  and a database-backed registry may want an asynchronous form. What **is** stable is the *data* they
  encode: the KeyId byte layout, wrapped-key handling, and therefore the readability of data already
  written. Only the API shapes may still change before `1.0`.

## Allowed Future Changes

Areas that may evolve after `1.0` without violating the promise:

- **Adding** new crypto suites by activating a reserved id (or registering a new one), new AAD schemes,
  new normalizers, or new envelope versions. New formats are introduced under a new id/version; existing
  ids and the version 1 layout are never repurposed, so old data keeps decrypting.
- **Promoting** preview features (KMS providers, re-encryption) to stable, at which point their then-current
  surface becomes covered.
- **Additive** API growth: new helper methods, new options with safe defaults, new analyzer rules and
  code fixes.
- Internal implementation, performance and diagnostics changes that do not alter a committed format or
  public contract.

## Breaking Changes Before 1.0

While still on `0.x`, the following changes are considered acceptable and may land before `1.0`. They are
listed so the intent is on record; none is guaranteed to happen.

- Moving `IKeyMaterialProvider` from `Proteos.Encryption.Core` to `Proteos.Encryption.Abstractions` for
  cleaner layering. (Currently expected to be left as-is, but allowed.)
- Adjusting the re-encryption (preview) API surface.
- Refining registration ergonomics and adding startup-time configuration validation.
- Analyzer message wording and rule scope.

The data formats under [Data Compatibility](#data-compatibility) are **not** on this list: they are
already treated as frozen, because data written by any released `0.1.x` build should remain readable by
`1.0`.

## Data Compatibility

This is the part that matters most. A change here is not a recompile — it can make stored data
permanently unreadable or silently break search. All of it is frozen for the 1.x line.

### Envelope

The version 1 binary layout is fixed:

```
Magic            4 bytes   "PENC" (0x50 0x45 0x4E 0x43)
Version          1 byte    (0x01)
CryptoSuiteId    1 byte
AadSchemeId      1 byte
KeyIdLength      1 byte    1..255
KeyId            N bytes
NonceLength      1 byte    1..255
Nonce            N bytes
TagLength        1 byte    1..255
Tag              N bytes
CiphertextLength 4 bytes   UInt32, big-endian
Ciphertext       N bytes
```

The header-bound AAD is `Version || CryptoSuiteId || AadSchemeId || KeyId`; the magic marker and the
length prefixes are framing and are deliberately not authenticated. The crypto-suite registry is closed:
`0x01` is `AES-256-GCM` (12-byte nonce, 16-byte tag); the reserved suite ids and the reserved
`ContextBound` AAD scheme id will never be reassigned. New behaviour arrives as a new version byte or a
new suite id, never by changing the meaning of an existing one.

### KeyId

The KeyId is an opaque, length-bounded (1..255 byte) identifier stored in the envelope; that opacity is
part of the format, so the catalogue — not the stored data — maps an id to a concrete key. The production
scheme is `TmkId (16 bytes) || Version (2 bytes, big-endian)` = 18 bytes, with a TmkId that is stable
across a tenant's key versions. This binding (tenant identity in the TmkId, rotation version in the
trailing two bytes) is frozen. The KeyId is also part of the AAD, so it cannot be altered without
authentication failing.

### Working-key derivation

Working keys are derived with HKDF-SHA256 from the tenant master key. The `info` is a length-prefixed
concatenation of the purpose token, the logical entity name and the logical property name:

```
info = LP("enc" | "idx") || LP(entityLogicalName) || LP(propertyLogicalName)
```

where each segment is prefixed with a 2-byte big-endian length, the output length is 32 bytes, and the
HKDF salt is empty. The purpose tokens are exactly `enc` (encryption) and `idx` (blind index). This
construction gives domain separation between purposes and between columns, and it is frozen: changing the
tokens, the segment order, the length-prefix encoding, the hash or the output length would change every
derived key and make stored data undecryptable.

### Blind Index

A blind index is `HMAC-SHA256(indexKey, normalizedValueUtf8)`, the full 32-byte output, never truncated,
where `indexKey` is derived with the `idx` purpose. The construction is frozen. Because a blind index is
deterministic it leaks equality and frequency by design (see the [threat model](threat-model.md)); that
is a documented property, not something a future change will "fix" by altering the construction.

### Normalizer

A blind index is computed over the **normalized** value, so the normalization rules are a data-format
commitment as strong as the hash itself: change them and existing indexes silently stop matching, with no
decryption error to signal it. The frozen rules are:

- **Default normalizer** — trim surrounding whitespace, then apply Unicode **NFC**. Case-sensitive,
  culture-invariant. Operation order is part of the contract: trim, then NFC.
- **Email normalizer** — trim surrounding whitespace, then lower-case with the invariant culture
  (`ToLowerInvariant`), then apply Unicode **NFC**. Operation order is part of the contract: trim,
  lower-case, then NFC.

Two points are explicit and frozen:

- **NFC, not NFKC.** Canonical composition only; compatibility folding (which would change, for example,
  ligatures or full-width forms) is intentionally not applied.
- **Invariant culture** for case folding, so behaviour never depends on the host's locale.

One honest caveat: Unicode normalization and invariant case folding ultimately rely on the Unicode tables
that ship with the .NET runtime. For ASCII and ordinary text this is stable; for unusual code points a
future runtime's updated tables could, in principle, normalize or case-fold a value differently and thus
change its blind index. Where an indexed field is an identifier you control (for example an account
reference), prefer ASCII to stay on the safe side.

## Upgrade Philosophy

The guiding preference is **slow, additive evolution over surprising data migrations.** A library that
encrypts data carries an obligation its consumers cannot easily discharge themselves: if a format changes,
they may be unable to read their own data. So:

- New capability is added beside the old, under a new version/id, rather than by changing an existing
  format. Old envelopes keep decrypting; new envelopes use the new path.
- A data-format change is a last resort. If one ever becomes unavoidable, it will come with a clear major
  version, an explicit migration path, and the ability to read both formats during the transition — never
  a silent change that requires a flag day.
- API breaks are reserved for major versions and kept few; preview features absorb the churn so the
  stable surface can stay still.

The intent is that data written by a `1.x` build is readable by every later `1.x` build, and that
upgrading is a dependency bump, not a project.
