using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// Explains strict mode and shows that it is satisfied here — without provoking an exception. Strict
/// mode is enabled with a single option; an unclassified property would then fail the save.
/// </summary>
public sealed class Scenario04_StrictMode : IScenario
{
    public string Title => "Strict mode";

    public async Task ExecuteAsync()
    {
        Console.WriteLine("Strict mode is opt-in, with one option:");
        Console.WriteLine();
        Console.WriteLine("    services.AddProteosEncryption(options =>");
        Console.WriteLine("    {");
        Console.WriteLine("        options.UseLocalDevelopmentKeyProvider();");
        Console.WriteLine("        options.UseSingleTenant(\"showcase\");");
        Console.WriteLine("        options.EnableStrictMode();   // <-- here");
        Console.WriteLine("    });");
        Console.WriteLine();
        Console.WriteLine("With strict mode ON, every string/byte[] property must be explicitly classified");
        Console.WriteLine("([Encrypted], [EncryptedSearchable], [EncryptedEmail] or [Plaintext]). An unclassified");
        Console.WriteLine("property would then fail the SaveChanges with one aggregated error listing every");
        Console.WriteLine("offender — no silent plaintext and no name-based guessing.");
        Console.WriteLine();

        // Customer is fully classified, so strict mode passes. We verify it safely (no exception):
        using var sp = ShowcaseHost.Build(ShowcaseHost.DevelopmentKey(), strictMode: true);
        using var scope = sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();

        var report = db.GetEncryptionAuditReport();
        Console.WriteLine($"Unclassified properties on Customer: {report.Unclassified.Count}.");

        db.Customers.Add(new Customer { Email = "ok@example.com", Name = "Strict Ok", Phone = "+49 0" });
        await db.SaveChangesAsync();
        Console.WriteLine("Saved successfully under strict mode (every property is classified).");
    }
}
