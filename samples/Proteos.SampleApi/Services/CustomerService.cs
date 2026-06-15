using Microsoft.EntityFrameworkCore;
using Proteos.SampleApi.Dtos;

namespace Proteos.SampleApi.Services;

/// <summary>
/// A normal service that reads and writes customers. There is almost nothing encryption-specific
/// here: Proteos encrypts on SaveChanges and decrypts on materialization underneath, so the service
/// works with plain values. The only encryption-aware calls are the two searches, which must go
/// through <c>WhereEncryptedEquals</c> instead of a plaintext LINQ comparison.
/// </summary>
public sealed class CustomerService : ICustomerService
{
    private readonly SampleDbContext _db;

    public CustomerService(SampleDbContext db) => _db = db;

    public async Task<CustomerResponse> CreateAsync(CreateCustomerRequest request, CancellationToken cancellationToken)
    {
        var customer = new Customer
        {
            Email = request.Email,
            Name = request.Name,
            Phone = request.Phone,
        };

        _db.Customers.Add(customer);

        // Proteos encrypts the [Encrypted*] properties automatically, just before they hit the database.
        await _db.SaveChangesAsync(cancellationToken);

        // After SaveChanges the tracked entity holds the ciphertext (encryption happens at the save
        // boundary), so the response is built from the request (plaintext) plus the new database id —
        // never from the saved entity.
        return new CustomerResponse(customer.Id, request.Email, request.Name, request.Phone);
    }

    public async Task<IReadOnlyList<CustomerResponse>> GetAllAsync(CancellationToken cancellationToken)
    {
        // Proteos decrypts the encrypted properties automatically as the rows are materialized.
        var customers = await _db.Customers.ToListAsync(cancellationToken);
        return customers.Select(ToResponse).ToList();
    }

    public async Task<CustomerResponse?> GetByIdAsync(int id, CancellationToken cancellationToken)
    {
        var customer = await _db.Customers.FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        return customer is null ? null : ToResponse(customer);
    }

    public async Task<CustomerResponse?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        // Email is [EncryptedEmail], so it is searchable. WhereEncryptedEquals compares the blind index,
        // NOT the plaintext. A normal .Where(c => c.Email == email) would compare against ciphertext in
        // the database and never match.
        var customer = await _db.Customers
            .WhereEncryptedEquals(_db, c => c.Email, email)
            .FirstOrDefaultAsync(cancellationToken);

        return customer is null ? null : ToResponse(customer);
    }

    public async Task<IReadOnlyList<CustomerResponse>> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        // Name is [EncryptedSearchable], so it is searchable too — through its own blind index.
        var customers = await _db.Customers
            .WhereEncryptedEquals(_db, c => c.Name, name)
            .ToListAsync(cancellationToken);

        return customers.Select(ToResponse).ToList();
    }

    // There is deliberately no FindByPhone: Phone is [Encrypted] only (no blind index), so it cannot
    // be searched by value. WhereEncryptedEquals(_db, c => c.Phone, ...) would throw, and a plain
    // .Where(c => c.Phone == "...") would compare ciphertext and never match.

    public IReadOnlyList<EncryptionAuditResponse> GetEncryptionAudit()
    {
        var report = _db.GetEncryptionAuditReport();
        return report.Entries
            .Select(entry => new EncryptionAuditResponse(
                entry.EntityClrType.Name,
                entry.PropertyName,
                entry.Classification.ToString()))
            .ToList();
    }

    private static CustomerResponse ToResponse(Customer customer) =>
        new(customer.Id, customer.Email, customer.Name, customer.Phone);
}
