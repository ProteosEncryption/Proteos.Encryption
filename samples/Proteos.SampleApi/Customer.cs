using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.SampleApi;

// [EncryptedEntity] gives the entity a stable logical name ("customer") that is bound into key
// derivation. It is required on any entity that has encrypted properties.
[EncryptedEntity("customer")]
public class Customer
{
    public int Id { get; set; }

    // Encrypted + searchable, with email normalization (lower-cased and trimmed before indexing),
    // so a search for "MAX@example.com " still matches "max@example.com".
    [EncryptedEmail("email")]
    public required string Email { get; set; }

    // Encrypted + searchable with an exact-match blind index.
    [EncryptedSearchable("name")]
    public required string Name { get; set; }

    // Encrypted only. There is no blind index, so this field cannot be searched.
    [Encrypted("phone")]
    public required string Phone { get; set; }
}
