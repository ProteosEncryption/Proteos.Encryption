using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi.Entities;

namespace Proteos.CrmSampleApi.Data;

public class CrmSampleDbContext : DbContext
{
    public CrmSampleDbContext(DbContextOptions<CrmSampleDbContext> options)
        : base(options)
    {
    }

    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<Contact> Contacts => Set<Contact>();
    public DbSet<Address> Addresses => Set<Address>();
    public DbSet<Order> Orders => Set<Order>();
    public DbSet<OrderNote> OrderNotes => Set<OrderNote>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Ordinary EF relationships. The point of this sample: the relationships are configured exactly
        // as in any app — Proteos only affects how individual sensitive columns are stored.
        modelBuilder.Entity<Customer>(customer =>
        {
            customer.HasMany(c => c.Contacts)
                .WithOne(c => c.Customer)
                .HasForeignKey(c => c.CustomerId)
                .OnDelete(DeleteBehavior.Cascade);

            customer.HasMany(c => c.Orders)
                .WithOne(o => o.Customer)
                .HasForeignKey(o => o.CustomerId)
                .OnDelete(DeleteBehavior.Cascade);

            // Optional one-to-one: a customer may have one address.
            customer.HasOne(c => c.Address)
                .WithOne(a => a.Customer)
                .HasForeignKey<Address>(a => a.CustomerId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Order>(order =>
        {
            order.HasMany(o => o.Notes)
                .WithOne(n => n.Order)
                .HasForeignKey(n => n.OrderId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Finalizes the Proteos encryption model (reads [Encrypted*]/[Plaintext] and builds the blind
        // index columns). Must be called after the relationships are configured.
        modelBuilder.UseProteosEncryptionModel();
    }
}
