using Microsoft.AspNetCore.Mvc;
using Proteos.CrmSampleApi.Dtos.Orders;
using Proteos.CrmSampleApi.Services.Orders;

namespace Proteos.CrmSampleApi.Controllers;

[ApiController]
public sealed class OrdersController : ControllerBase
{
    private readonly IOrderService _orders;

    public OrdersController(IOrderService orders) => _orders = orders;

    /// <summary>Create an order for a customer.</summary>
    [HttpPost("api/customers/{customerId:int}/orders")]
    public async Task<ActionResult<OrderDto>> CreateOrder(int customerId, CreateOrderRequest request, CancellationToken ct)
    {
        try
        {
            var order = await _orders.CreateOrderAsync(customerId, request, ct);
            return CreatedAtAction(nameof(GetById), new { id = order.Id }, order);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }

    /// <summary>Get one order with its notes (EF Include).</summary>
    [HttpGet("api/orders/{id:int}")]
    public async Task<ActionResult<OrderDto>> GetById(int id, CancellationToken ct)
    {
        var order = await _orders.GetByIdAsync(id, ct);
        return order is null ? NotFound() : Ok(order);
    }

    /// <summary>Find orders by encrypted reference (WhereEncryptedEquals).</summary>
    [HttpGet("api/orders/search/reference")]
    public async Task<IReadOnlyList<OrderDto>> SearchByReference([FromQuery] string reference, CancellationToken ct) =>
        await _orders.FindByReferenceAsync(reference, ct);

    /// <summary>Add a note to an order.</summary>
    [HttpPost("api/orders/{orderId:int}/notes")]
    public async Task<ActionResult<OrderNoteDto>> AddNote(int orderId, CreateOrderNoteRequest request, CancellationToken ct)
    {
        try
        {
            var note = await _orders.AddNoteAsync(orderId, request, ct);
            return Created($"/api/orders/{orderId}/notes/{note.Id}", note);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
    }
}
