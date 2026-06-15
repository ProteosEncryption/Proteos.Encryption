using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi.Data;
using Proteos.CrmSampleApi.Dtos.Contacts;
using Proteos.CrmSampleApi.Entities;

namespace Proteos.CrmSampleApi.Services.Contacts;

public sealed class ContactService : IContactService
{
    private readonly CrmSampleDbContext _db;

    public ContactService(CrmSampleDbContext db) => _db = db;

    public async Task<ContactDto> AddContactAsync(int customerId, CreateContactRequest request, CancellationToken ct)
    {
        if (!await _db.Customers.AnyAsync(c => c.Id == customerId, ct))
        {
            throw new KeyNotFoundException($"Customer {customerId} does not exist.");
        }

        var contact = new Contact
        {
            CustomerId = customerId,
            FullName = request.FullName,
            Email = request.Email,
            Phone = request.Phone,
            Role = request.Role,
        };

        _db.Contacts.Add(contact);
        await _db.SaveChangesAsync(ct);

        // Built from the request (plaintext) + new id; the tracked entity now holds ciphertext.
        return new ContactDto(contact.Id, customerId, request.FullName, request.Email, request.Phone, request.Role);
    }

    public async Task<IReadOnlyList<ContactDto>> FindByEmailAsync(string email, CancellationToken ct)
    {
        var contacts = await _db.Contacts
            .WhereEncryptedEquals(_db, c => c.Email, email)
            .OrderBy(c => c.Id)
            .ToListAsync(ct);

        return contacts.Select(ToDto).ToList();
    }

    public async Task<IReadOnlyList<ContactDto>> FindByNameAsync(string name, CancellationToken ct)
    {
        var contacts = await _db.Contacts
            .WhereEncryptedEquals(_db, c => c.FullName, name)
            .OrderBy(c => c.Id)
            .ToListAsync(ct);

        return contacts.Select(ToDto).ToList();
    }

    private static ContactDto ToDto(Contact c) =>
        new(c.Id, c.CustomerId, c.FullName, c.Email, c.Phone, c.Role);
}
