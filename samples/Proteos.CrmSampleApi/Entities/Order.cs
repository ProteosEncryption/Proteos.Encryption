using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.CrmSampleApi.Entities;

[EncryptedEntity("order")]
public class Order
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public Customer Customer { get; set; } = null!;

    [Plaintext]
    public string OrderNumber { get; set; } = "";

    [EncryptedSearchable("reference")]
    public string Reference { get; set; } = "";

    [Encrypted("internalComment")]
    public string InternalComment { get; set; } = "";

    public DateTime CreatedAtUtc { get; set; }

    public List<OrderNote> Notes { get; set; } = [];
}
