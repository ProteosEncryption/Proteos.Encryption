using Microsoft.AspNetCore.Mvc;
using Proteos.CrmSampleApi.Dtos.Contacts;
using Proteos.CrmSampleApi.Services.Contacts;

namespace Proteos.CrmSampleApi.Controllers;

// Routes span two resources (a customer's contacts, and contact search), so they are declared per
// action rather than under a single controller-level [Route].
[ApiController]
public sealed class ContactsController : ControllerBase
{
    private readonly IContactService _contacts;

    public ContactsController(IContactService contacts) => _contacts = contacts;

    /// <summary>Add a contact to a customer.</summary>
    [HttpPost("api/customers/{customerId:int}/contacts")]
    public async Task<ActionResult<ContactDto>> AddContact(int customerId, CreateContactRequest request, CancellationToken ct)
    {
        try
        {
            var contact = await _contacts.AddContactAsync(customerId, request, ct);
            return Created($"/api/contacts/{contact.Id}", contact);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    /// <summary>Find contacts by encrypted email (WhereEncryptedEquals).</summary>
    [HttpGet("api/contacts/search/email")]
    public async Task<IReadOnlyList<ContactDto>> SearchByEmail([FromQuery] string email, CancellationToken ct) =>
        await _contacts.FindByEmailAsync(email, ct);

    /// <summary>Find contacts by encrypted full name (WhereEncryptedEquals).</summary>
    [HttpGet("api/contacts/search/name")]
    public async Task<IReadOnlyList<ContactDto>> SearchByName([FromQuery] string name, CancellationToken ct) =>
        await _contacts.FindByNameAsync(name, ct);
}
