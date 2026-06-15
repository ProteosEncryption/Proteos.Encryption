using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.CrmSampleApi.Entities;

[EncryptedEntity("address")]
public class Address
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public Customer Customer { get; set; } = null!;

    [Encrypted("street")]
    public string Street { get; set; } = "";

    [Encrypted("city")]
    public string City { get; set; } = "";

    [Encrypted("postalCode")]
    public string PostalCode { get; set; } = "";

    [Plaintext]
    public string CountryCode { get; set; } = "DE";
}
