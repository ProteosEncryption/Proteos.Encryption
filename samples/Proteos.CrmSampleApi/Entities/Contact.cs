using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.CrmSampleApi.Entities;

[EncryptedEntity("contact")]
public class Contact
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public Customer Customer { get; set; } = null!;

    [EncryptedSearchable("fullName")]
    public string FullName { get; set; } = "";

    [EncryptedEmail("email")]
    public string Email { get; set; } = "";

    // Encrypted only — no blind index, so phone cannot be searched.
    [Encrypted("phone")]
    public string Phone { get; set; } = "";

    [Plaintext]
    public string Role { get; set; } = "";
}
