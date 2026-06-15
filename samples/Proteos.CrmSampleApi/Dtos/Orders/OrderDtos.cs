namespace Proteos.CrmSampleApi.Dtos.Orders;

public sealed record CreateOrderRequest(string OrderNumber, string Reference, string InternalComment);

public sealed record CreateOrderNoteRequest(string Text);

public sealed record OrderNoteDto(int Id, int OrderId, string Text, DateTime CreatedAtUtc);

public sealed record OrderDto(
    int Id,
    int CustomerId,
    string OrderNumber,
    string Reference,
    string InternalComment,
    DateTime CreatedAtUtc,
    IReadOnlyList<OrderNoteDto> Notes);
