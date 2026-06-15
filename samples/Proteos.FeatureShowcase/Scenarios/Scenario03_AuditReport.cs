using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// Prints the encryption audit report — how every string/byte[] property of the model is classified.
/// Derived purely from the EF model, so it needs no database access.
/// </summary>
public sealed class Scenario03_AuditReport : IScenario
{
    public string Title => "Audit report";

    public Task ExecuteAsync()
    {
        using var sp = ShowcaseHost.Build(ShowcaseHost.DevelopmentKey());
        using var scope = sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();

        var report = db.GetEncryptionAuditReport();

        Console.WriteLine($"{"Property",-20} {"Classification",-22}");
        Console.WriteLine(new string('-', 42));
        foreach (var entry in report.Entries)
        {
            Console.WriteLine($"{entry.Path,-20} {entry.Classification,-22}");
        }

        Console.WriteLine();
        Console.WriteLine("Classifications: Encrypted, EncryptedSearchable, Plaintext (marked [Plaintext]),");
        Console.WriteLine($"Unclassified (none here). Unclassified count: {report.Unclassified.Count}.");

        return Task.CompletedTask;
    }
}
