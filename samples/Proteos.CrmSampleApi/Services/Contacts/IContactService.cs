using Proteos.CrmSampleApi.Dtos.Contacts;

namespace Proteos.CrmSampleApi.Services.Contacts;

public interface IContactService
{
    /// <summary>Adds a contact to a customer. Throws <see cref="KeyNotFoundException"/> if the customer is unknown.</summary>
    Task<ContactDto> AddContactAsync(int customerId, CreateContactRequest request, CancellationToken ct);

    /// <summary>Finds contacts by their encrypted email (WhereEncryptedEquals).</summary>
    Task<IReadOnlyList<ContactDto>> FindByEmailAsync(string email, CancellationToken ct);

    /// <summary>Finds contacts by their encrypted full name (WhereEncryptedEquals).</summary>
    Task<IReadOnlyList<ContactDto>> FindByNameAsync(string name, CancellationToken ct);

    // Note: there is deliberately no FindByPhone — Phone is [Encrypted] only (no blind index).
}
