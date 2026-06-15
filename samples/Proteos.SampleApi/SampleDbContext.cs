using Microsoft.EntityFrameworkCore;

namespace Proteos.SampleApi;

public class SampleDbContext : DbContext
{
    public SampleDbContext(DbContextOptions<SampleDbContext> options)
        : base(options)
    {
    }

    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Finalizes the Proteos encryption model: reads the [Encrypted*] attributes and creates the
        // hidden blind-index columns used for equality search. Nothing else is configured here.
        modelBuilder.UseProteosEncryptionModel();
    }
}
