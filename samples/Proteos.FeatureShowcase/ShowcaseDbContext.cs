using Microsoft.EntityFrameworkCore;

namespace Proteos.FeatureShowcase;

public class ShowcaseDbContext : DbContext
{
    public ShowcaseDbContext(DbContextOptions<ShowcaseDbContext> options)
        : base(options)
    {
    }

    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Reads the [Encrypted*] attributes and creates the hidden blind-index columns. That is the
        // only encryption-related line in the entire data model.
        modelBuilder.UseProteosEncryptionModel();
    }
}
