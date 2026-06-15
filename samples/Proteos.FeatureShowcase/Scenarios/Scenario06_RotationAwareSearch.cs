using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// Rotation-aware search. Two customers share the same name but were saved under different key
/// versions, so their blind indexes differ. The search recomputes the term's index under every known
/// key version, so a single query still finds both rows.
/// </summary>
public sealed class Scenario06_RotationAwareSearch : IScenario
{
    public string Title => "Rotation-aware search";

    public async Task ExecuteAsync()
    {
        // Save one "Max Mustermann" under the v1 current key...
        using (var sp = ShowcaseHost.Build(ShowcaseHost.Rotating(currentVersion: 1)))
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
            db.Customers.Add(new Customer { Email = "old@example.com", Name = "Max Mustermann", Phone = "+49 1" });
            await db.SaveChangesAsync();
        }

        // ...and another under the v2 current key.
        using (var sp = ShowcaseHost.Build(ShowcaseHost.Rotating(currentVersion: 2)))
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            db.Customers.Add(new Customer { Email = "new@example.com", Name = "Max Mustermann", Phone = "+49 2" });
            await db.SaveChangesAsync();
        }

        // Search under the rotated provider (current v2, still knows v1). It builds the blind index for
        // the term under every known version and ORs them, so both the v1 and the v2 row match.
        using (var sp = ShowcaseHost.Build(ShowcaseHost.Rotating(currentVersion: 2)))
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            var matches = await db.Customers
                .WhereEncryptedEquals(db, x => x.Name, "Max Mustermann")
                .ToListAsync();
            Console.WriteLine($"Search returned {matches.Count} customers.");
        }
    }
}
