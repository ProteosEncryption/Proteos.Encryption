using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.FeatureShowcase;

// The single demo entity. Each attribute is a different classification:
//   [EncryptedEmail]      -> encrypted + searchable, email-normalized
//   [EncryptedSearchable] -> encrypted + searchable (exact match)
//   [Encrypted]           -> encrypted only, NOT searchable
// [EncryptedEntity] supplies the stable logical name bound into key derivation; it is required on
// any entity with encrypted properties. (Properties use `required` so the model is null-safe; this
// is functionally identical to `public string Email { get; set; }`.)
[EncryptedEntity("customer")]
public class Customer
{
    public int Id { get; set; }

    [EncryptedEmail("email")]
    public required string Email { get; set; }

    [EncryptedSearchable("name")]
    public required string Name { get; set; }

    [Encrypted("phone")]
    public required string Phone { get; set; }
}
