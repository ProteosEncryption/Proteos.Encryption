using Proteos.CrmSampleApi.Dtos.Contacts;
using Proteos.CrmSampleApi.Dtos.Orders;

namespace Proteos.CrmSampleApi.Dtos.Customers;

public sealed record CreateAddressRequest(string Street, string City, string PostalCode, string CountryCode);

public sealed record AddressDto(int Id, string Street, string City, string PostalCode, string CountryCode);

public sealed record CreateCustomerRequest(
    string CustomerNumber,
    string CompanyName,
    string BillingEmail,
    string TaxNumber,
    CreateAddressRequest? Address);

/// <summary>Lean projection for list endpoints (decrypted on read).</summary>
public sealed record CustomerListItemDto(
    int Id,
    string CustomerNumber,
    string CompanyName,
    string BillingEmail);

/// <summary>Full customer with its related contacts, address and orders (loaded with EF Include).</summary>
public sealed record CustomerDetailDto(
    int Id,
    string CustomerNumber,
    string CompanyName,
    string BillingEmail,
    string TaxNumber,
    AddressDto? Address,
    IReadOnlyList<ContactDto> Contacts,
    IReadOnlyList<OrderDto> Orders);
