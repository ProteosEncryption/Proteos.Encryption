namespace Proteos.CrmSampleApi.Dtos.Contacts;

public sealed record CreateContactRequest(string FullName, string Email, string Phone, string Role);

public sealed record ContactDto(int Id, int CustomerId, string FullName, string Email, string Phone, string Role);
