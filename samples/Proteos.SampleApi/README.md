# Proteos Sample API

A minimal ASP.NET Core Web API that shows how a real application uses **Proteos Application Layer
Encryption** with Entity Framework Core — through a normal **Controller → Service → DbContext** flow.
It is deliberately small; you should be able to read the whole thing in a few minutes.

It uses a controller and a thin service. There is **no** repository layer, CQRS, MediatR, AutoMapper,
auth, or Docker — just enough to be realistic.

## What it demonstrates

1. Create a customer (values encrypted on save)
2. Load customers (encrypted values decrypted automatically on read)
3. Search by **encrypted email**
4. Search by **encrypted name**
5. `Phone` is **encrypted-only** and therefore not searchable
6. An **encryption audit** showing how every property is classified

> ⚠️ This sample uses the **LocalDevelopmentKeyProvider**, which keeps a fixed key in memory.
> Never use it in production — use **Azure Key Vault** or **AWS KMS** instead.

## How it fits together

| File | Role |
| --- | --- |
| [`Customer.cs`](Customer.cs) | Entity with encrypted fields (`[EncryptedEmail]`, `[EncryptedSearchable]`, `[Encrypted]`) |
| [`SampleDbContext.cs`](SampleDbContext.cs) | DbContext — `modelBuilder.UseProteosEncryptionModel()` |
| [`Services/CustomerService.cs`](Services/CustomerService.cs) | Application logic: save, load, search, audit |
| [`Controllers/CustomersController.cs`](Controllers/CustomersController.cs) | HTTP endpoints under `/api/customers` |
| [`Dtos/`](Dtos) | Request/response records (the API never exposes the entity directly) |
| [`Program.cs`](Program.cs) | Wires up controllers, the service, the DbContext and Proteos |

Encryption happens **just before** rows are written to SQLite and decryption happens **as** they are
read back. Plaintext never reaches the database, and the searches never send plaintext either — only
a one-way hash (the *blind index*) is compared in SQL.

### Searchable vs. encrypted-only — and why `WhereEncryptedEquals`

| Property | Attribute | Searchable? |
| --- | --- | --- |
| `Email` | `[EncryptedEmail("email")]` | ✅ yes (blind index, email-normalized) |
| `Name` | `[EncryptedSearchable("name")]` | ✅ yes (blind index) |
| `Phone` | `[Encrypted("phone")]` | ❌ no — encrypted only |

A normal LINQ comparison on an encrypted field is **wrong**:

```csharp
// ❌ Wrong: compares the plaintext term against the CIPHERTEXT stored in the column — never matches.
db.Customers.Where(c => c.Email == "max@example.com");
```

The correct way is `WhereEncryptedEquals`, which normalizes and hashes the term and compares it
against the property's blind index:

```csharp
// ✅ Right: matches via the blind index.
db.Customers.WhereEncryptedEquals(db, c => c.Email, "max@example.com");
```

`Phone` has no blind index, so it has no search endpoint: calling `WhereEncryptedEquals` on it would
throw, and a plain `.Where(c => c.Phone == "...")` would compare ciphertext and never match.

## Endpoints

| Method | Route | Description |
| --- | --- | --- |
| `POST` | `/api/customers` | Create a customer |
| `GET` | `/api/customers` | Get all customers |
| `GET` | `/api/customers/{id}` | Get one customer by id |
| `GET` | `/api/customers/search/email?email=…` | Search by encrypted email |
| `GET` | `/api/customers/search/name?name=…` | Search by encrypted name |
| `GET` | `/api/customers/encryption-audit` | Show the property classification |

## Run

```bash
dotnet run
```

The API listens on `http://localhost:5000`. On first run it creates `sample.db` and seeds three
customers (Max Mustermann, Anna Müller, John Smith), so the list and search endpoints have data to
return right away.

### Create a customer

```bash
curl -X POST http://localhost:5000/api/customers \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"erika@example.com\",\"name\":\"Erika Beispiel\",\"phone\":\"+49 654321\"}"
```

### Get all customers (decrypted)

`GET /api/customers` returns the **full list**. Every encrypted field is decrypted automatically as
the rows are materialized — `GetAllAsync()` just calls `ToListAsync()`, with no decryption code of
its own.

```bash
curl http://localhost:5000/api/customers
```

```json
[
  { "id": 1, "email": "max@example.com",  "name": "Max Mustermann", "phone": "+49 123456" },
  { "id": 2, "email": "anna@example.com", "name": "Anna Müller",    "phone": "+49 234567" },
  { "id": 3, "email": "john@example.com", "name": "John Smith",     "phone": "+49 345678" }
]
```

Open `sample.db` in any SQLite viewer and the `Email`, `Name` and `Phone` columns hold ciphertext,
not these strings.

### Search by encrypted email

```bash
curl "http://localhost:5000/api/customers/search/email?email=max@example.com"
```

Email search is case- and whitespace-insensitive (the email normalizer), so this matches the same
row:

```bash
curl "http://localhost:5000/api/customers/search/email?email=%20MAX@example.com%20"
```

### Search by encrypted name

`GET /api/customers/search/name` runs an **encrypted search** — `FindByNameAsync()` calls
`WhereEncryptedEquals(db, x => x.Name, name)`, which compares the blind index instead of the
plaintext — and returns the matches as a **list**. The match is exact (after normalization), so pass
the full name:

```bash
curl "http://localhost:5000/api/customers/search/name?name=Max%20Mustermann"
```

```json
[
  { "id": 1, "email": "max@example.com", "name": "Max Mustermann", "phone": "+49 123456" }
]
```

### Encryption audit

```bash
curl http://localhost:5000/api/customers/encryption-audit
```

```json
[
  { "entity": "Customer", "property": "Email", "classification": "EncryptedSearchable" },
  { "entity": "Customer", "property": "Name",  "classification": "EncryptedSearchable" },
  { "entity": "Customer", "property": "Phone", "classification": "Encrypted" }
]
```

## Reset

Delete the database to start fresh:

```bash
rm sample.db
```
