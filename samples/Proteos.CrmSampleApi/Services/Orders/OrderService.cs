using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi.Data;
using Proteos.CrmSampleApi.Dtos.Orders;
using Proteos.CrmSampleApi.Entities;

namespace Proteos.CrmSampleApi.Services.Orders;

public sealed class OrderService : IOrderService
{
    private readonly CrmSampleDbContext _db;

    public OrderService(CrmSampleDbContext db) => _db = db;

    public async Task<OrderDto> CreateOrderAsync(int customerId, CreateOrderRequest request, CancellationToken ct)
    {
        if (!await _db.Customers.AnyAsync(c => c.Id == customerId, ct))
        {
            throw new KeyNotFoundException($"Customer {customerId} does not exist.");
        }

        var order = new Order
        {
            CustomerId = customerId,
            OrderNumber = request.OrderNumber,
            Reference = request.Reference,
            InternalComment = request.InternalComment,
            CreatedAtUtc = DateTime.UtcNow,
        };

        _db.Orders.Add(order);
        await _db.SaveChangesAsync(ct);

        return new OrderDto(order.Id, customerId, request.OrderNumber, request.Reference, request.InternalComment, order.CreatedAtUtc, Array.Empty<OrderNoteDto>());
    }

    public async Task<OrderDto?> GetByIdAsync(int id, CancellationToken ct)
    {
        var order = await _db.Orders
            .Include(o => o.Notes)
            .FirstOrDefaultAsync(o => o.Id == id, ct);

        return order is null ? null : ToDto(order);
    }

    public async Task<IReadOnlyList<OrderDto>> FindByReferenceAsync(string reference, CancellationToken ct)
    {
        var orders = await _db.Orders
            .WhereEncryptedEquals(_db, o => o.Reference, reference)
            .Include(o => o.Notes)
            .OrderBy(o => o.Id)
            .ToListAsync(ct);

        return orders.Select(ToDto).ToList();
    }

    public async Task<OrderNoteDto> AddNoteAsync(int orderId, CreateOrderNoteRequest request, CancellationToken ct)
    {
        if (!await _db.Orders.AnyAsync(o => o.Id == orderId, ct))
        {
            throw new KeyNotFoundException($"Order {orderId} does not exist.");
        }

        var note = new OrderNote
        {
            OrderId = orderId,
            Text = request.Text,
            CreatedAtUtc = DateTime.UtcNow,
        };

        _db.OrderNotes.Add(note);
        await _db.SaveChangesAsync(ct);

        return new OrderNoteDto(note.Id, orderId, request.Text, note.CreatedAtUtc);
    }

    private static OrderDto ToDto(Order o) =>
        new(
            o.Id,
            o.CustomerId,
            o.OrderNumber,
            o.Reference,
            o.InternalComment,
            o.CreatedAtUtc,
            o.Notes.OrderBy(n => n.Id).Select(n => new OrderNoteDto(n.Id, n.OrderId, n.Text, n.CreatedAtUtc)).ToList());
}
