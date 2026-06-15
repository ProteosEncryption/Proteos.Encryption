using Microsoft.AspNetCore.Mvc;
using Proteos.SampleApi.Dtos;
using Proteos.SampleApi.Services;

namespace Proteos.SampleApi.Controllers;

[ApiController]
[Route("api/customers")]
public sealed class CustomersController : ControllerBase
{
    private readonly ICustomerService _customers;

    public CustomersController(ICustomerService customers) => _customers = customers;

    /// <summary>Create a customer. The values are encrypted before they are stored.</summary>
    [HttpPost]
    public async Task<ActionResult<CustomerResponse>> Create(CreateCustomerRequest request, CancellationToken cancellationToken)
    {
        var created = await _customers.CreateAsync(request, cancellationToken);
        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }

    /// <summary>Get all customers, with their encrypted values decrypted.</summary>
    [HttpGet]
    public async Task<IReadOnlyList<CustomerResponse>> GetAll(CancellationToken cancellationToken) =>
        await _customers.GetAllAsync(cancellationToken);

    /// <summary>Get one customer by id.</summary>
    [HttpGet("{id:int}")]
    public async Task<ActionResult<CustomerResponse>> GetById(int id, CancellationToken cancellationToken)
    {
        var customer = await _customers.GetByIdAsync(id, cancellationToken);
        return customer is null ? NotFound() : Ok(customer);
    }

    /// <summary>Search by encrypted email. Uses the blind index, not a plaintext comparison.</summary>
    [HttpGet("search/email")]
    public async Task<ActionResult<CustomerResponse>> SearchByEmail([FromQuery] string email, CancellationToken cancellationToken)
    {
        var customer = await _customers.FindByEmailAsync(email, cancellationToken);
        return customer is null ? NotFound() : Ok(customer);
    }

    /// <summary>Search by encrypted name. Also uses a blind index.</summary>
    [HttpGet("search/name")]
    public async Task<IReadOnlyList<CustomerResponse>> SearchByName([FromQuery] string name, CancellationToken cancellationToken) =>
        await _customers.FindByNameAsync(name, cancellationToken);

    // There is deliberately no search endpoint for Phone: it is [Encrypted] only (no blind index),
    // so it cannot be queried by value.

    /// <summary>Show how each property of the model is classified (encrypted / searchable / plaintext).</summary>
    [HttpGet("encryption-audit")]
    public IReadOnlyList<EncryptionAuditResponse> GetEncryptionAudit() => _customers.GetEncryptionAudit();
}
