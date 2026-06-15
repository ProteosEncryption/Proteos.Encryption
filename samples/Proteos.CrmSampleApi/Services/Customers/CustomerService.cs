using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi.Data;
using Proteos.CrmSampleApi.Dtos.Contacts;
using Proteos.CrmSampleApi.Dtos.Customers;
using Proteos.CrmSampleApi.Dtos.Orders;
using Proteos.CrmSampleApi.Entities;

namespace Proteos.CrmSampleApi.Services.Customers;

public sealed class CustomerService : ICustomerService
{
    private readonly CrmSampleDbContext _db;

    public CustomerService(CrmSampleDbContext db) => _db = db;

    public async Task<CustomerDetailDto> CreateAsync(CreateCustomerRequest request, CancellationToken ct)
    {
        var customer = new Customer
        {
            CustomerNumber = request.CustomerNumber,
            CompanyName = request.CompanyName,
            BillingEmail = request.BillingEmail,
            TaxNumber = request.TaxNumber,
        };

        if (request.Address is { } address)
        {
            customer.Address = new Address
            {
                Street = address.Street,
                City = address.City,
                PostalCode = address.PostalCode,
                CountryCode = address.CountryCode,
            };
        }

        _db.Customers.Add(customer);

        // Proteos encrypts every [Encrypted*] property automatically on SaveChanges.
        await _db.SaveChangesAsync(ct);

        // After SaveChanges the tracked entity holds ciphertext, so the response is built from the
        // request (plaintext) plus the generated ids — never from the saved entity.
        return new CustomerDetailDto(
            customer.Id,
            request.CustomerNumber,
            request.CompanyName,
            request.BillingEmail,
            request.TaxNumber,
            customer.Address is null
                ? null
                : new AddressDto(customer.Address.Id, request.Address!.Street, request.Address.City, request.Address.PostalCode, request.Address.CountryCode),
            Array.Empty<ContactDto>(),
            Array.Empty<OrderDto>());
    }

    public async Task<IReadOnlyList<CustomerListItemDto>> GetAllAsync(CancellationToken ct)
    {
        var customers = await _db.Customers.OrderBy(c => c.Id).ToListAsync(ct);
        return customers.Select(ToListItem).ToList();
    }

    public async Task<CustomerDetailDto?> GetByIdAsync(int id, CancellationToken ct)
    {
        var customer = await IncludeGraph(_db.Customers)
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        return customer is null ? null : ToDetail(customer);
    }

    public async Task<CustomerDetailDto?> FindByBillingEmailAsync(string email, CancellationToken ct)
    {
        // BillingEmail is [EncryptedEmail], so it is searchable. WhereEncryptedEquals matches via the
        // blind index; a normal .Where(c => c.BillingEmail == email) would compare ciphertext.
        var customer = await IncludeGraph(_db.Customers.WhereEncryptedEquals(_db, c => c.BillingEmail, email))
            .FirstOrDefaultAsync(ct);

        return customer is null ? null : ToDetail(customer);
    }

    public async Task<IReadOnlyList<CustomerListItemDto>> FindByCompanyNameAsync(string companyName, CancellationToken ct)
    {
        var customers = await _db.Customers
            .WhereEncryptedEquals(_db, c => c.CompanyName, companyName)
            .OrderBy(c => c.Id)
            .ToListAsync(ct);

        return customers.Select(ToListItem).ToList();
    }

    public async Task<IReadOnlyList<CustomerListItemDto>> FindByCompanyNamesAsync(IReadOnlyList<string> companyNames, CancellationToken ct)
    {
        // WhereEncryptedIn is the encrypted-search equivalent of SQL IN (...): match any of the names.
        var customers = await _db.Customers
            .WhereEncryptedIn(_db, c => c.CompanyName, companyNames)
            .OrderBy(c => c.Id)
            .ToListAsync(ct);

        return customers.Select(ToListItem).ToList();
    }

    private static IQueryable<Customer> IncludeGraph(IQueryable<Customer> source) =>
        source
            .Include(c => c.Address)
            .Include(c => c.Contacts)
            .Include(c => c.Orders)
            .ThenInclude(o => o.Notes);

    private static CustomerListItemDto ToListItem(Customer c) =>
        new(c.Id, c.CustomerNumber, c.CompanyName, c.BillingEmail);

    private static CustomerDetailDto ToDetail(Customer c) =>
        new(
            c.Id,
            c.CustomerNumber,
            c.CompanyName,
            c.BillingEmail,
            c.TaxNumber,
            c.Address is null ? null : new AddressDto(c.Address.Id, c.Address.Street, c.Address.City, c.Address.PostalCode, c.Address.CountryCode),
            c.Contacts.Select(contact => new ContactDto(contact.Id, contact.CustomerId, contact.FullName, contact.Email, contact.Phone, contact.Role)).ToList(),
            c.Orders
                .OrderBy(o => o.Id)
                .Select(o => new OrderDto(
                    o.Id,
                    o.CustomerId,
                    o.OrderNumber,
                    o.Reference,
                    o.InternalComment,
                    o.CreatedAtUtc,
                    o.Notes.OrderBy(n => n.Id).Select(n => new OrderNoteDto(n.Id, n.OrderId, n.Text, n.CreatedAtUtc)).ToList()))
                .ToList());
}
