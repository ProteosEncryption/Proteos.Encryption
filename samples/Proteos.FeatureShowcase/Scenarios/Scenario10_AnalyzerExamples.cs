using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// The Roslyn analyzer that ships with the EF package flags encrypted-property misuse at compile
/// time. The examples are kept as comments so this project always compiles cleanly.
/// </summary>
public sealed class Scenario10_AnalyzerExamples : IScenario
{
    public string Title => "Analyzer examples";

    public Task ExecuteAsync()
    {
        // The analyzer reports these at compile time (examples kept as comments — no live misuse):
        //
        //   // PENC001 — projecting an encrypted property returns ciphertext:
        //   db.Customers.Select(x => x.Email);
        //
        //   // PENC002 — comparing an encrypted property with == never matches:
        //   db.Customers.Where(x => x.Email == email);
        //
        //   // Correct — use the blind-index search helper:
        //   db.Customers.WhereEncryptedEquals(db, x => x.Email, email);

        Console.WriteLine("The Proteos analyzer ships with the EF package and flags encrypted-property misuse");
        Console.WriteLine("at compile time:");
        Console.WriteLine();
        Console.WriteLine("  PENC001 — projecting an encrypted property returns ciphertext:");
        Console.WriteLine("      db.Customers.Select(x => x.Email);            // warning PENC001");
        Console.WriteLine();
        Console.WriteLine("  PENC002 — comparing an encrypted property with == never matches:");
        Console.WriteLine("      db.Customers.Where(x => x.Email == email);    // warning PENC002");
        Console.WriteLine();
        Console.WriteLine("  Correct — use the blind-index search helper:");
        Console.WriteLine("      db.Customers.WhereEncryptedEquals(db, x => x.Email, email);");
        Console.WriteLine();
        Console.WriteLine("(PENC003 is reserved for a future strict-mode rule.)");

        return Task.CompletedTask;
    }
}
