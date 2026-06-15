using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.CrmSampleApi.Entities;

[EncryptedEntity("customer")]
public class Customer
{
    public int Id { get; set; }

    [EncryptedSearchable("companyName")]
    public string CompanyName { get; set; } = "";

    [EncryptedEmail("billingEmail")]
    public string BillingEmail { get; set; } = "";

    [Encrypted("taxNumber")]
    public string TaxNumber { get; set; } = "";

    // Not sensitive: a public-facing customer number, deliberately stored in plaintext so it is
    // human-readable in the database and could be used as a normal key/filter.
    [Plaintext]
    public string CustomerNumber { get; set; } = "";

    // One-to-one (optional). Added to the model so GetById can Include the address; the foreign key
    // lives on Address. The encryption of address fields is independent of the relationship.
    public Address? Address { get; set; }

    public List<Contact> Contacts { get; set; } = [];

    public List<Order> Orders { get; set; } = [];
}
