# Threat Model

Proteos.Encryption is application-layer encryption (ALE) for .NET: sensitive entity fields are encrypted
inside the application before they reach the database, backups or cloud storage. This document defines
precisely what that protects against, what it does not, the assumptions it relies on, and the
cryptographic construction it uses. This is the canonical threat model for Proteos.Encryption; read it
before relying on Proteos for sensitive data.

← [Back to README](../README.md) · See also [Limitations](limitations.md), [Querying](querying.md),
[Key rotation](key-rotation.md).

## Summary

Proteos protects the **confidentiality of individual field values at rest**. Anyone who can *read* the
stored data — a leaked database, a backup, a cloud-storage bucket, a read-only data pipeline, or a
curious database administrator or cloud operator who does not have access to the key-management service
(KMS) — sees only ciphertext. Proteos does **not** protect against an attacker who controls the running
application, who can read its process memory, or who holds both the stored data and the ability to use
the KMS.

## What it protects

- **Database compromise (read access).** A dump, a stolen replica, or SQL read access exposes ciphertext
  envelopes, not plaintext.
- **Backup and cloud-storage compromise.** Offline backups, snapshots and object-storage copies contain
  only ciphertext for encrypted fields.
- **Curious DBA / cloud operator.** Someone with read access to the database or storage, but without KMS
  access, cannot recover plaintext.
- **Read-only data pipelines.** ETL jobs, analytics replicas and log shippers that copy the stored
  columns carry ciphertext, not plaintext.
- **Accidental relocation.** A value encrypted for one entity/property cannot be silently moved to a
  different column and still decrypt: the logical entity and property are bound into key derivation.
- **Tenant isolation.** A ciphertext of one tenant cannot be decrypted with another tenant's key;
  resolution fails closed.

## What it does not protect

- **A compromised application server (e.g. remote code execution).** The running application can derive
  keys and reach the KMS, so an attacker who controls it can decrypt. ALE protects data at rest, not a
  compromised runtime.
- **Process memory.** Plaintext, derived keys and unwrapped master keys exist transiently in process
  memory during an operation. A memory dump or a debugger attached to the live process can observe them.
- **A compromised client.** Proteos encrypts server-side; it does not protect data on a device or in a
  browser. It is not end-to-end encryption (see below).
- **Stolen credentials with KMS access.** An attacker who obtains both the stored data and credentials
  that can use the KMS key can unwrap master keys and decrypt. The KMS is the trust anchor.
- **Active database manipulation.** Integrity is per value, not database-wide. An attacker with write
  access can delete, duplicate, reorder or replace whole rows; Proteos detects tampering *within* a value
  but does not protect the structure or completeness of the database. It is not a substitute for access
  control, auditing or backups.
- **Ciphertext-size analysis.** Ciphertext length reveals the approximate plaintext length.

## Application-layer encryption vs end-to-end encryption

Proteos is **not** end-to-end encryption (E2EE). In E2EE only the communicating endpoints hold keys and
the server never sees plaintext. In ALE the application server *does* see plaintext — it performs the
encryption and decryption — and holds the ability to derive keys. ALE narrows exposure to "whoever can
use the keys", which keeps plaintext out of the database, backups and storage, but it places trust in the
application and the KMS. If your threat model requires that the server never sees plaintext, ALE is not
the right tool.

## Trust model

The security of stored data reduces to **the secrecy of, and access control over, the key-encryption key
(KEK) in the KMS.** The key hierarchy is:

- **KEK** — held in the KMS (Azure Key Vault, AWS KMS, Google Cloud KMS). It never leaves the KMS; it
  only wraps and unwraps tenant master keys. This is the root of trust.
- **Tenant master key (TMK)** — one per tenant, stored only in wrapped form. It is unwrapped transiently
  to derive working keys, then zeroed.
- **Working keys** — derived per tenant, purpose and scope; used for one operation and zeroed.

Whoever can perform a KMS unwrap with the KEK can recover master keys and therefore plaintext. Protect
KMS access accordingly: least privilege, audit logging and alerting. The development key provider
(`LocalDevelopmentKeyProvider`) has no KMS — it derives everything from a single root key and is for
development and tests only.

## Key ownership and key loss

- **You own the keys.** Keys live in your KMS under your control; Proteos never transmits key material
  off your infrastructure.
- **Key loss is data loss.** If the KEK is destroyed or becomes permanently unavailable, every value
  wrapped under it is unrecoverable. This is by design — it makes crypto-shredding (deleting a key to
  render its data unreadable) possible — but it means KEK durability, backup and break-glass procedures
  are your responsibility. Treat KEK availability as a first-class operational concern.

## Memory exposure

Plaintext values, derived working keys and unwrapped tenant master keys exist in managed memory for the
duration of an operation. Proteos zeroes derived keys and unwrapped master keys after use, and zeroes
plaintext buffers on a failed authentication, but managed strings produced on decryption are immutable
and cannot be wiped. Anything able to read process memory — a dump, a debugger, a malicious in-process
component — can therefore observe plaintext and keys while they are live. ALE does not defend against an
attacker at that level.

## Blind index leakage

Exact-match search uses a **blind index**: `HMAC-SHA256(indexKey, normalizedValue)`, where the index key
is derived separately from the encryption key. A blind index is one-way (it cannot be reversed to the
plaintext) and stores no plaintext, but it is **deterministic**: equal inputs produce equal index values.
It therefore **leaks equality and frequency** — an observer of the stored index column can tell which
rows share a value and how often each distinct value occurs, without learning the value itself. Do not
place a blind index on a field where equality or frequency disclosure is unacceptable.

## Integrity model

Proteos uses authenticated encryption (AES-256-GCM). Each value is bound to its envelope header and key
identity through additional authenticated data (AAD), and to its logical entity, property and tenant
through key derivation. Decryption **fails** — rather than returning a wrong value — if the ciphertext,
tag, header, key id, tenant or scope does not match.

This integrity is **per value, not database-wide.** Proteos guarantees that a given stored value was not
altered and was written for the expected tenant and column. It does **not** guarantee that rows were not
added, deleted, duplicated or reordered, and it is not a database-integrity or anti-tamper mechanism for
the store as a whole. Use database access control, transaction logs and backups for those properties.

## Cryptographic construction

- **Cipher:** AES-256-GCM (authenticated encryption with associated data); 256-bit keys, 128-bit
  authentication tag.
- **Nonce:** 96-bit (12-byte), drawn from a cryptographically secure random source, fresh per encryption.
- **Nonce collision / budget:** GCM security depends on never reusing a (key, nonce) pair. With random
  96-bit nonces the birthday bound makes collisions a practical concern only after roughly **2³²**
  encryptions under the *same derived key*. Working keys are derived per tenant, scope and key version,
  so this budget applies per column, per tenant, per version; extremely high-volume columns should plan
  key rotation accordingly.
- **Key derivation:** HKDF-SHA256. Working keys are derived from the tenant master key with a
  length-prefixed `info` that binds the purpose (`enc` / `idx`), the logical entity and the logical
  property — giving domain separation between purposes and between columns.
- **Blind index:** HMAC-SHA256 over the normalized value; the full 32-byte output, never truncated.
- **AAD binding:** the envelope header — version, crypto-suite id, AAD-scheme id and key id — is the
  additional authenticated data, so a value cannot be reinterpreted under a different version, suite or
  key id without authentication failing. The logical scope and tenant are bound through key derivation
  rather than through the AAD.

These are standard, widely reviewed primitives used in conventional ways. Proteos makes no novel
cryptographic claims.

## What you must configure correctly

- **Use a KMS-backed key provider in production.** `LocalDevelopmentKeyProvider` is insecure by design.
- **Protect KMS access** with least privilege and auditing; the KEK is the trust anchor.
- **Resolve the correct tenant** for every operation. A wrong or missing tenant resolver breaks tenant
  isolation or fails operations; validate it at startup where possible.
- **Classify every sensitive field.** Use the audit report and strict mode so nothing is written in
  plaintext by omission.
- **Avoid the query foot-guns.** Projections of encrypted properties return ciphertext, and `==`
  comparison never matches; use the provided search helpers (see [Querying](querying.md)). Bulk and raw
  operations (`ExecuteUpdate` / `ExecuteDelete`, raw SQL) bypass the interceptors and neither encrypt nor
  decrypt (see [Limitations](limitations.md)).
- **Plan key durability and rotation.** Back up KEK access, rotate keys deliberately, and remember that
  key loss is data loss.

## Claims to avoid

When describing a system that uses Proteos, do not claim:

- **"End-to-end encrypted"** — it is application-layer encryption; the server sees plaintext.
- **"Zero-knowledge"** or **"the server cannot read the data"** — the application can decrypt.
- **"Tamper-proof database"** or **"immutable"** — integrity is per value, not database-wide.
- Vague superlatives such as **"military-grade"** or **"unbreakable"** — they say nothing and misstate the
  actual guarantees.

State instead what is true: sensitive fields are encrypted at the application layer with AES-256-GCM, so
database, backup and storage reads expose only ciphertext, and the keys are held in your KMS.

## Audit status

Proteos.Encryption has not undergone an independent third-party security audit. Its design uses standard,
well-reviewed primitives (AES-256-GCM, HKDF-SHA256, HMAC-SHA256) and is covered by unit, negative and
known-answer tests, but the implementation has not been formally reviewed by an external party. Evaluate
it against your own requirements before relying on it for sensitive data.

---

For the deeper design rationale, see the
[architecture specification](architecture/application-layer-encryption-foundation.md). To report a
vulnerability, see [SECURITY.md](../SECURITY.md).
