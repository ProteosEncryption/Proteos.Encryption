# Querying encrypted fields

Encrypted columns hold random ciphertext: the same value encrypts to different bytes every time, so
the database cannot compare, order or pattern-match them. Exact-match search is supported through a
**blind index**; everything else is not (see [Limitations](limitations.md)).

← [Back to README](../README.md)

## Exact-match search

```csharp
var customer = await db.Customers
    .WhereEncryptedEquals(db, x => x.Email, "max@example.com")
    .FirstOrDefaultAsync();
```

- `WhereEncryptedEquals` normalizes the search term and computes its **blind index**
  (`HMAC-SHA256(indexKey, normalize(term))`), then filters the internal index column for it.
- The **database never sees the plaintext** — only the keyed hash, passed as a query parameter.
- The whole predicate translates to SQL (`WHERE EmailIndex = @p`); there is no client-side evaluation.
- The blind index column (`EmailIndex`) stays **internal** — you never name it; the helper handles it.
- Chain calls to AND conditions: `.WhereEncryptedEquals(db, x => x.Email, e).WhereEncryptedEquals(db, x => x.Alias, a)`.

The selector must be a direct property access (`x => x.Email`). The property must be configured as
searchable (`[EncryptedEmail]` / `[EncryptedSearchable]`), otherwise it is a hard error.

A blind index is deterministic and therefore **leaks equality and frequency** by design (two equal
values produce the same index). It does not leak the plaintext.

## Matching several values (`WhereEncryptedIn`)

The encrypted-search equivalent of SQL `IN (...)`: match a property against any of several terms.

```csharp
var customers = await db.Customers
    .WhereEncryptedIn(db, x => x.Email, new[] { "max@example.com", "mary@example.com" })
    .ToListAsync();
```

- Each term is normalized and blind-indexed exactly as on write, under **all known key versions**, and
  every resulting index is OR-ed into one server-side predicate (no client-side evaluation).
- Identical indexes are de-duplicated, so repeated or equal-normalizing terms do not bloat the query.
- An **empty** collection matches nothing; a `null` entry is a hard error (a blind index of null does
  not exist). Filter nulls out, or query them with `.Where(x => x.Property == null)`.

## Email convenience (`WhereEncryptedEmail`)

A thin, intent-revealing wrapper over `WhereEncryptedEquals` for email fields — identical mechanics
(the property's configured Email normalizer is applied):

```csharp
var customer = await db.Customers
    .WhereEncryptedEmail(db, x => x.Email, "max@example.com")
    .FirstOrDefaultAsync();
```

## Rotation-aware search

After a [key rotation](key-rotation.md), older rows carry a blind index from an older key version.
`WhereEncryptedEquals` therefore computes the term's index under **all known key versions** and ORs
them:

```text
EmailIndex == idxV1  OR  EmailIndex == idxV2  OR  EmailIndex == idxV3
```

With a single key version it stays a plain equality. Rows under a version the current provider no
longer knows are simply not matched — the query does not blow up.

## What not to do

**Do not project an encrypted property directly:**

```csharp
// ❌ returns ciphertext — projections bypass the decryption interceptor
var emails = await db.Customers.Select(x => x.Email).ToListAsync();
```

Decryption happens only when a **full entity** is materialized. Materialize the entity and read the
property from it, then project in memory if needed.

**Do not compare an encrypted property with `==` in a query:**

```csharp
// ❌ never matches — the column holds random ciphertext, not the plaintext
var c = await db.Customers.Where(x => x.Email == "max@example.com").FirstOrDefaultAsync();
```

Use `WhereEncryptedEquals` instead.

## The analyzer catches these

The analyzers bundled in the EF Core package flag both footguns at compile time:

| ID | Warns about |
|---|---|
| `PENC001` | Projecting an encrypted property (`Select(x => x.Email)`) — returns ciphertext. |
| `PENC002` | Comparing an encrypted property with `==`/`!=` in a query — use `WhereEncryptedEquals`. |
| `PENC003` | Reserved for a future strict-mode rule. |

They recognise both **attribute-based** configuration and the **simple fluent form**
(`.Property(x => x.Email).IsEncrypted(...)` / `.IsEncryptedSearchable(...)` / `.IsEncryptedEmail(...)`),
on **direct** member access only — see [Limitations](limitations.md).
