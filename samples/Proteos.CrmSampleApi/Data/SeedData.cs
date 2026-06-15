using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi.Entities;

namespace Proteos.CrmSampleApi.Data;

/// <summary>Seeds two customers with contacts, an address, orders and notes — only when the database is empty.</summary>
public static class SeedData
{
    public static async Task SeedAsync(CrmSampleDbContext db)
    {
        if (await db.Customers.AnyAsync())
        {
            return;
        }

        var alpha = new Customer
        {
            CustomerNumber = "C-1001",
            CompanyName = "Alpha Cleaning GmbH",
            BillingEmail = "billing@alpha-cleaning.example",
            TaxNumber = "DE123456789",
            Address = new Address { Street = "Putzstraße 1", City = "Berlin", PostalCode = "10115", CountryCode = "DE" },
            Contacts =
            {
                new Contact { FullName = "Max Mustermann", Email = "max@alpha-cleaning.example", Phone = "+49 30 1234567", Role = "Owner" },
            },
            Orders =
            {
                new Order
                {
                    OrderNumber = "O-2026-001",
                    Reference = "WINDOW-2026-001",
                    InternalComment = "VIP customer — handle with priority.",
                    CreatedAtUtc = DateTime.UtcNow,
                    Notes = { new OrderNote { Text = "Quoted on-site; awaiting signature.", CreatedAtUtc = DateTime.UtcNow } },
                },
            },
        };

        var beta = new Customer
        {
            CustomerNumber = "C-1002",
            CompanyName = "Beta Facility Services",
            BillingEmail = "billing@beta-facility.example",
            TaxNumber = "DE987654321",
            Address = new Address { Street = "Hausmeisterweg 7", City = "Hamburg", PostalCode = "20095", CountryCode = "DE" },
            Contacts =
            {
                new Contact { FullName = "Anna Müller", Email = "anna@beta-facility.example", Phone = "+49 40 7654321", Role = "Manager" },
            },
            Orders =
            {
                new Order
                {
                    OrderNumber = "O-2026-002",
                    Reference = "FLOOR-2026-002",
                    InternalComment = "Net-30 payment terms agreed.",
                    CreatedAtUtc = DateTime.UtcNow,
                    Notes = { new OrderNote { Text = "Scheduled for next week.", CreatedAtUtc = DateTime.UtcNow } },
                },
            },
        };

        db.Customers.AddRange(alpha, beta);
        await db.SaveChangesAsync();
    }
}
