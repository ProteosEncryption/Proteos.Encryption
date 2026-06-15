# Proteos CRM Sample API

A small but **realistic** CRM web API that shows how you would use Proteos Application Layer
Encryption in a real application — multiple related entities, services, controllers and DTOs — not a
single object. Where [`Proteos.SampleApi`](../Proteos.SampleApi) is the 5‑minute quickstart and
[`Proteos.FeatureShowcase`](../Proteos.FeatureShowcase) is the feature tour, this is the
"how does it look in an app?" sample.

It is intentionally just **Service + Controller** — no repository layer, CQRS, MediatR or
clean-architecture scaffolding.

> ⚠️ Uses the **LocalDevelopmentKeyProvider** (a fixed in-memory key). Never use it in production —
> use Azure Key Vault or AWS KMS.

## What this sample shows

- **Multiple models with relationships**: `Customer` → `Contacts`, `Customer` → `Orders` →
  `OrderNotes`, `Customer` → `Address` (one-to-one). Plain EF relationships work normally while
  sensitive columns are encrypted.
- **EF `Include`**: `GET /api/customers/{id}` loads the full graph (address, contacts, orders, notes),
  all decrypted automatically.
- **Three field classifications**:
  - *encrypted + searchable* — `CompanyName`, `BillingEmail`, `Contact.FullName`/`Email`,
    `Order.Reference`
  - *encrypted only* (not searchable) — `TaxNumber`, `Contact.Phone`, `Address.*`,
    `Order.InternalComment`, `OrderNote.Text`
  - *plaintext* (deliberate) — `CustomerNumber`, `Contact.Role`, `Order.OrderNumber`,
    `Address.CountryCode`
- **Encrypted search**: `WhereEncryptedEquals` (by email, company, name, reference) and
  `WhereEncryptedIn` (match any of several company names).
- **Strict mode**: enabled globally — every string/`byte[]` property must be classified, or the save
  fails. The audit endpoint shows there are no unclassified properties.
- **Audit report**, **raw database preview** (proves ciphertext at rest), and the
  **re-encryption foundation** — all under `/api/admin`.

### encrypted searchable vs. encrypted-only

A *searchable* field (`[EncryptedSearchable]` / `[EncryptedEmail]`) gets a blind index, so it can be
found with `WhereEncryptedEquals` / `WhereEncryptedIn`. An *encrypted-only* field (`[Encrypted]`) has
no index and **cannot be searched** — for example `Contact.Phone` has no search endpoint. A normal
`Where(x => x.Field == value)` on any encrypted column is wrong: it compares random-nonce ciphertext
and never matches.

## Run

```bash
cd samples/Proteos.CrmSampleApi
dotnet run
```

The API listens on `http://localhost:5100` and opens **Swagger UI** at `/swagger`. On first run it
creates `crm-sample.db` and seeds two customers (Alpha Cleaning GmbH, Beta Facility Services) with
contacts, addresses, orders and notes — only when the database is empty.

## Endpoints

### Customers
| Method | Route | Notes |
| --- | --- | --- |
| POST | `/api/customers` | create (with optional address) |
| GET | `/api/customers` | list (lean) |
| GET | `/api/customers/{id}` | detail with Include |
| GET | `/api/customers/search/email?email=…` | `WhereEncryptedEquals` |
| GET | `/api/customers/search/company?name=…` | `WhereEncryptedEquals` |
| GET | `/api/customers/search/companies?name=…&name=…` | `WhereEncryptedIn` |

### Contacts
| Method | Route | Notes |
| --- | --- | --- |
| POST | `/api/customers/{customerId}/contacts` | add a contact |
| GET | `/api/contacts/search/email?email=…` | `WhereEncryptedEquals` |
| GET | `/api/contacts/search/name?name=…` | `WhereEncryptedEquals` |

### Orders
| Method | Route | Notes |
| --- | --- | --- |
| POST | `/api/customers/{customerId}/orders` | create an order |
| GET | `/api/orders/{id}` | order with notes (Include) |
| GET | `/api/orders/search/reference?reference=…` | `WhereEncryptedEquals` |
| POST | `/api/orders/{orderId}/notes` | add a note |

### Admin
| Method | Route | Notes |
| --- | --- | --- |
| GET | `/api/admin/encryption-audit` | property classification |
| GET | `/api/admin/raw-preview` | proof of ciphertext at rest |
| GET | `/api/admin/reencryption-status` | re-encryption foundation |

## Example requests

```bash
# Find a customer by encrypted billing email (returns the full graph)
curl "http://localhost:5100/api/customers/search/email?email=billing@alpha-cleaning.example"

# Find by encrypted company name
curl "http://localhost:5100/api/customers/search/company?name=Beta%20Facility%20Services"

# WhereEncryptedIn: match any of several company names
curl "http://localhost:5100/api/customers/search/companies?name=Alpha%20Cleaning%20GmbH&name=Beta%20Facility%20Services"

# Find contacts by encrypted name (Phone has no search — it is encrypted-only)
curl "http://localhost:5100/api/contacts/search/name?name=Anna%20M%C3%BCller"

# Find orders by encrypted reference
curl "http://localhost:5100/api/orders/search/reference?reference=FLOOR-2026-002"

# Add a contact
curl -X POST http://localhost:5100/api/customers/2/contacts \
  -H "Content-Type: application/json" \
  -d "{\"fullName\":\"Test Person\",\"email\":\"test@beta-facility.example\",\"phone\":\"+49 40 0000\",\"role\":\"Assistant\"}"
```

### Audit report

```bash
curl http://localhost:5100/api/admin/encryption-audit
```

Every string property is classified — `EncryptedSearchable`, `Encrypted` or `Plaintext`, with **no**
`Unclassified` (strict mode would otherwise reject saves).

### Raw preview — ciphertext at rest

```bash
curl http://localhost:5100/api/admin/raw-preview
```

```json
{
  "note": "Encrypted columns are stored as Base64 Proteos 'PENC' envelopes; previews are truncated. ...",
  "plaintextLeakDetected": false,
  "columns": [
    { "table": "Customers", "column": "CompanyName", "storedValuePreview": "UEVOQwEB…", "isProteosEnvelope": true },
    ...
  ]
}
```

The stored values are Base64 `PENC` envelopes; `plaintextLeakDetected` is `false` — none of the seed
plaintext appears in the database. (Values are truncated; no full secret is printed.)

### Re-encryption status (rotation foundation)

```bash
curl http://localhost:5100/api/admin/reencryption-status
```

With this sample's single-version development key, all values are under the current key
(`valuesNeedingReEncryption: 0`). After a key rotation, the planner (`IEncryptionMigrationPlanner`)
would count the values written under the old key — by reading the envelope header only, no decryption
— and a re-encrypt worker would migrate them. Full rotation is demonstrated in
[`Proteos.FeatureShowcase`](../Proteos.FeatureShowcase).

## Reset

```bash
rm crm-sample.db
```
