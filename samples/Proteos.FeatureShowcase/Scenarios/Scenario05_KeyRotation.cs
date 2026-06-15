using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// Key rotation. Save Customer A while the current key is v1, switch the current key to v2, save
/// Customer B, then read both back. The provider still holds v1, so the older row stays decryptable.
/// </summary>
public sealed class Scenario05_KeyRotation : IScenario
{
    public string Title => "Key rotation";

    public async Task ExecuteAsync()
    {
        var currentV1 = ShowcaseHost.Rotating(currentVersion: 1);
        var currentV2 = ShowcaseHost.Rotating(currentVersion: 2);

        // 1) Current key is v1 -> Customer A is stamped with v1.
        using (var sp = ShowcaseHost.Build(currentV1))
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
            db.Customers.Add(new Customer { Email = "a@example.com", Name = "Customer A", Phone = "+49 1" });
            await db.SaveChangesAsync();
            Console.WriteLine($"Customer A -> v{currentV1.CurrentVersion}");
        }

        // 2) Rotate the current key to v2 -> Customer B is stamped with v2.
        using (var sp = ShowcaseHost.Build(currentV2))
        {
            using (var scope = sp.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
                db.Customers.Add(new Customer { Email = "b@example.com", Name = "Customer B", Phone = "+49 2" });
                await db.SaveChangesAsync();
                Console.WriteLine($"Customer B -> v{currentV2.CurrentVersion}");
            }

            // 3) Read both back in a fresh scope. v2's provider still knows v1, so A and B both decrypt.
            using (var scope = sp.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
                var all = await db.Customers.OrderBy(c => c.Id).ToListAsync();
                var names = string.Join(", ", all.Select(c => $"{c.Name} ({c.Email})"));
                Console.WriteLine($"Both decrypted successfully: {names}");
            }
        }
    }
}
