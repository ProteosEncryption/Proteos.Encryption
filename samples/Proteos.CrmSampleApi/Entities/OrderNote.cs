using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.CrmSampleApi.Entities;

[EncryptedEntity("orderNote")]
public class OrderNote
{
    public int Id { get; set; }

    public int OrderId { get; set; }

    public Order Order { get; set; } = null!;

    [Encrypted("text")]
    public string Text { get; set; } = "";

    public DateTime CreatedAtUtc { get; set; }
}
