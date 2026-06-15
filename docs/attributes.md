# Attributes

Mark sensitive properties directly on the entity. Attributes and the [Fluent API](fluent-api.md) are
**equivalent** — pick whichever fits your codebase.

← [Back to README](../README.md)

```csharp
[EncryptedEntity("customer")]
public class Customer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]   // encrypted + searchable, email normalizer
    public string Email { get; set; } = "";

    [Encrypted("phone")]        // encrypted only
    public string Phone { get; set; } = "";

    [Plaintext]                 // deliberately stored in clear (see strict mode)
    public string DisplayName { get; set; } = "";
}
```

## Logical names

Every attribute takes an explicit **logical name**:

- **Entity logical name** — `[EncryptedEntity("customer")]`, once per entity that has encrypted properties.
- **Property logical name** — `[Encrypted("phone")]`.

These names are bound into key derivation. They are **deliberately explicit and never derived from the
CLR type or property name**, so renaming a C# class or property does **not** make stored data
unreadable or unsearchable. Treat a logical name as permanent once data exists.

## The attributes

| Attribute | Meaning |
|---|---|
| `[EncryptedEntity("name")]` | Declares the entity's logical name. Required on any entity with encrypted properties. |
| `[Encrypted("name")]` | Property stored encrypted (string or `byte[]`). |
| `[EncryptedSearchable("name")]` | Encrypted **and** searchable via a blind index. String only. Optional `Normalizer` and `IndexProperty`. |
| `[EncryptedEmail("name")]` | Shorthand for `[EncryptedSearchable("name", Normalizer = Email)]` (trim + invariant lower-case + NFC). |
| `[Plaintext]` | The property is deliberately **not** encrypted. A conscious classification, not "don't care" — used by [strict mode](audit-and-strict-mode.md). |

`[EncryptedSearchable]` and `[EncryptedEmail]` derive from `[Encrypted]`: searchable always implies
encrypted, so you never combine them.

## Shadow properties and auto-index

A searchable property needs a column to store its blind index. By default this is created
**automatically** as an EF Core **shadow property** named `{Property}Index` (`byte[]`, nullable,
32 bytes) — you do **not** declare it on your class:

```csharp
[EncryptedEmail("email")]
public string Email { get; set; } = "";
// → internal shadow column "EmailIndex" + a non-unique database index for fast equality search
```

Power users can point at an existing `byte[]` CLR property instead:
`[EncryptedSearchable("email", IndexProperty = nameof(EmailIndex))]`.

You normally never reference `EmailIndex` — searching goes through `WhereEncryptedEquals` (see
[Querying](querying.md)).

## Why scope and normalizer stay explicit

The logical names and the normalizer feed the cryptographic identity of a field. Inferring them from
CLR names would mean a refactor (a rename) silently re-keys the data and breaks decryption and search.
Making them explicit trades a little verbosity for rename-safety. Defining a property in **both** an
attribute and the fluent API with conflicting settings is a hard error at model build.
