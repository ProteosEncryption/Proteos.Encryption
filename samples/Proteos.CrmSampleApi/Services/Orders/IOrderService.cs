using Proteos.CrmSampleApi.Dtos.Orders;

namespace Proteos.CrmSampleApi.Services.Orders;

public interface IOrderService
{
    /// <summary>Creates an order for a customer. Throws <see cref="KeyNotFoundException"/> if the customer is unknown.</summary>
    Task<OrderDto> CreateOrderAsync(int customerId, CreateOrderRequest request, CancellationToken ct);

    /// <summary>Loads one order with its notes (EF Include).</summary>
    Task<OrderDto?> GetByIdAsync(int id, CancellationToken ct);

    /// <summary>Finds orders by their encrypted reference (WhereEncryptedEquals).</summary>
    Task<IReadOnlyList<OrderDto>> FindByReferenceAsync(string reference, CancellationToken ct);

    /// <summary>Adds a note to an order. Throws <see cref="KeyNotFoundException"/> if the order is unknown.</summary>
    Task<OrderNoteDto> AddNoteAsync(int orderId, CreateOrderNoteRequest request, CancellationToken ct);
}
