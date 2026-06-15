using Proteos.CrmSampleApi.Dtos.Customers;

namespace Proteos.CrmSampleApi.Services.Customers;

public interface ICustomerService
{
    Task<CustomerDetailDto> CreateAsync(CreateCustomerRequest request, CancellationToken ct);

    Task<IReadOnlyList<CustomerListItemDto>> GetAllAsync(CancellationToken ct);

    /// <summary>Loads one customer with its contacts, address and orders (EF Include).</summary>
    Task<CustomerDetailDto?> GetByIdAsync(int id, CancellationToken ct);

    /// <summary>Finds a customer by its encrypted billing email (WhereEncryptedEquals).</summary>
    Task<CustomerDetailDto?> FindByBillingEmailAsync(string email, CancellationToken ct);

    /// <summary>Finds customers by their encrypted company name (WhereEncryptedEquals).</summary>
    Task<IReadOnlyList<CustomerListItemDto>> FindByCompanyNameAsync(string companyName, CancellationToken ct);

    /// <summary>Finds customers matching any of several encrypted company names (WhereEncryptedIn).</summary>
    Task<IReadOnlyList<CustomerListItemDto>> FindByCompanyNamesAsync(IReadOnlyList<string> companyNames, CancellationToken ct);
}
