namespace Proteos.SampleApi.Dtos;

/// <summary>
/// What a client sends to create a customer. These are plain values; encryption happens later, in
/// the database layer — the API and service never deal with ciphertext.
/// </summary>
public sealed record CreateCustomerRequest(
    string Email,
    string Name,
    string Phone);
