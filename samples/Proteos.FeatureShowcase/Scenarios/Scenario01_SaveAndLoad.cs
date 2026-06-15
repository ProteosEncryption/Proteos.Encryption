using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// The core promise: save and load an entity with encrypted fields and write no crypto code yourself.
/// Proteos encrypts on SaveChanges and decrypts on materialization. Ends by reading the raw column to
/// prove the database holds ciphertext.
/// </summary>
public sealed class Scenario01_SaveAndLoad : IScenario
{
    public string Title => "Save and load";

    public async Task ExecuteAsync()
    {
        using var sp = ShowcaseHost.Build(ShowcaseHost.DevelopmentKey());

        // Save. No encryption code here — Proteos encrypts the [Encrypted*] properties on SaveChanges.
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();

            db.Customers.Add(new Customer { Email = "max@example.com", Name = "Max Mustermann", Phone = "+49 123456" });
            await db.SaveChangesAsync();
            Console.WriteLine("Customer saved.");
        }

        // Load in a FRESH scope (fresh change tracker), so the row is materialized from disk and
        // decrypted, rather than served as the still-tracked entity from the save above.
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            var loaded = await db.Customers.FirstAsync();
            Console.WriteLine("Customer loaded.");
            Console.WriteLine($"Email: {loaded.Email}");
        }

        // Prove the database itself stores ciphertext, not the plaintext printed above.
        Console.WriteLine();
        RawDatabaseInspector.PrintRawValue("Email", "max@example.com");
    }
}
