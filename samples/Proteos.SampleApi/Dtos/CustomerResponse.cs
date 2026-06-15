namespace Proteos.SampleApi.Dtos;

/// <summary>
/// What the API returns. The values are already decrypted — Proteos decrypts the encrypted
/// properties automatically when the rows are read from the database.
/// </summary>
public sealed record CustomerResponse(
    int Id,
    string Email,
    string Name,
    string Phone);
