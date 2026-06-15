using Microsoft.AspNetCore.Mvc;
using Proteos.CrmSampleApi.Dtos.Customers;
using Proteos.CrmSampleApi.Services.Customers;

namespace Proteos.CrmSampleApi.Controllers;

[ApiController]
[Route("api/customers")]
public sealed class CustomersController : ControllerBase
{
    private readonly ICustomerService _customers;

    public CustomersController(ICustomerService customers) => _customers = customers;

    /// <summary>Create a customer (and optionally its address). Sensitive fields are encrypted on save.</summary>
    [HttpPost]
    public async Task<ActionResult<CustomerDetailDto>> Create(CreateCustomerRequest request, CancellationToken ct)
    {
        var created = await _customers.CreateAsync(request, ct);
        return CreatedAtAction(nameof(GetById), new { id = created.Id }, created);
    }

    /// <summary>List all customers (lean projection, decrypted).</summary>
    [HttpGet]
    public async Task<IReadOnlyList<CustomerListItemDto>> GetAll(CancellationToken ct) =>
        await _customers.GetAllAsync(ct);

    /// <summary>Get one customer with contacts, address and orders (EF Include).</summary>
    [HttpGet("{id:int}")]
    public async Task<ActionResult<CustomerDetailDto>> GetById(int id, CancellationToken ct)
    {
        var customer = await _customers.GetByIdAsync(id, ct);
        return customer is null ? NotFound() : Ok(customer);
    }

    /// <summary>Find a customer by encrypted billing email (WhereEncryptedEquals).</summary>
    [HttpGet("search/email")]
    public async Task<ActionResult<CustomerDetailDto>> SearchByEmail([FromQuery] string email, CancellationToken ct)
    {
        var customer = await _customers.FindByBillingEmailAsync(email, ct);
        return customer is null ? NotFound() : Ok(customer);
    }

    /// <summary>Find customers by encrypted company name (WhereEncryptedEquals).</summary>
    [HttpGet("search/company")]
    public async Task<IReadOnlyList<CustomerListItemDto>> SearchByCompany([FromQuery] string name, CancellationToken ct) =>
        await _customers.FindByCompanyNameAsync(name, ct);

    /// <summary>Find customers matching any of several company names (WhereEncryptedIn), e.g. ?name=Alpha%20Cleaning%20GmbH&amp;name=Beta%20Facility%20Services.</summary>
    [HttpGet("search/companies")]
    public async Task<IReadOnlyList<CustomerListItemDto>> SearchByCompanies([FromQuery] string[] name, CancellationToken ct) =>
        await _customers.FindByCompanyNamesAsync(name, ct);
}
