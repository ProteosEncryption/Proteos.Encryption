using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// Equality search over encrypted fields with <c>WhereEncryptedEquals</c> — by email and by name —
/// and an explanation of why a normal LINQ comparison on an encrypted column is wrong.
/// </summary>
public sealed class Scenario02_EncryptedSearch : IScenario
{
    public string Title => "Encrypted search";

    public async Task ExecuteAsync()
    {
        using var sp = ShowcaseHost.Build(ShowcaseHost.DevelopmentKey());

        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
            db.Customers.AddRange(
                new Customer { Email = "max@example.com", Name = "Max Mustermann", Phone = "+49 1" },
                new Customer { Email = "anna@example.com", Name = "Anna Müller", Phone = "+49 2" });
            await db.SaveChangesAsync();
        }

        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();

            var byEmail = await db.Customers
                .WhereEncryptedEquals(db, x => x.Email, "max@example.com")
                .FirstOrDefaultAsync();
            Console.WriteLine($"Search by email \"max@example.com\" -> found: {byEmail?.Name}");

            var byName = await db.Customers
                .WhereEncryptedEquals(db, x => x.Name, "Anna Müller")
                .FirstOrDefaultAsync();
            Console.WriteLine($"Search by name  \"Anna Müller\"      -> found: {byName?.Email}");
        }

        Console.WriteLine();
        Console.WriteLine("Why not a normal LINQ comparison?");
        Console.WriteLine("    // WRONG:");
        Console.WriteLine("    // db.Customers.Where(x => x.Email == email)");
        Console.WriteLine("  The Email column stores random-nonce ciphertext, so a plaintext '==' never matches.");
        Console.WriteLine("  WhereEncryptedEquals hashes the term into the blind index and compares THAT in SQL.");
    }
}
