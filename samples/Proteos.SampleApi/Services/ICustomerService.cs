using Proteos.SampleApi.Dtos;

namespace Proteos.SampleApi.Services;

/// <summary>
/// The application service the controller talks to. It works entirely with plain values and DTOs;
/// the encryption is handled transparently by Proteos in the database layer.
/// </summary>
public interface ICustomerService
{
    Task<CustomerResponse> CreateAsync(CreateCustomerRequest request, CancellationToken cancellationToken);

    Task<IReadOnlyList<CustomerResponse>> GetAllAsync(CancellationToken cancellationToken);

    Task<CustomerResponse?> GetByIdAsync(int id, CancellationToken cancellationToken);

    /// <summary>Find a customer by its encrypted, searchable email.</summary>
    Task<CustomerResponse?> FindByEmailAsync(string email, CancellationToken cancellationToken);

    /// <summary>Find customers by their encrypted, searchable name.</summary>
    Task<IReadOnlyList<CustomerResponse>> FindByNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>Classification of every string/byte[] property in the model (encrypted / searchable / plaintext).</summary>
    IReadOnlyList<EncryptionAuditResponse> GetEncryptionAudit();
}
