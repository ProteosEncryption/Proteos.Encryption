using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// Azure Key Vault setup — example only. No credentials, nothing is called. Shows the real
/// registration API so a developer knows exactly what to add for production.
/// </summary>
public sealed class Scenario08_AzureSetupExample : IScenario
{
    public string Title => "Azure Key Vault setup";

    public Task ExecuteAsync()
    {
        // ---------------------------------------------------------------------------------------
        // Example only. This code is NOT executed here — it needs a real Key Vault and credentials.
        //
        //   // Add the package: Proteos.Encryption.AzureKeyVault
        //
        //   services.AddProteosAzureKeyVault(options =>
        //   {
        //       options.KeyIdentifier = new Uri(
        //           "https://my-vault.vault.azure.net/keys/proteos-kek/abcdef0123");
        //       // options.Credential defaults to DefaultAzureCredential when omitted.
        //   });
        //
        // The rest of the wiring (AddProteosEncryption + AddDbContext + UseProteosEncryption) is the
        // same as the development setup used by the other scenarios.
        // ---------------------------------------------------------------------------------------

        Console.WriteLine("Example only — no real credentials, nothing is called.");
        Console.WriteLine();
        Console.WriteLine("Add the package:  Proteos.Encryption.AzureKeyVault");
        Console.WriteLine();
        Console.WriteLine("    services.AddProteosAzureKeyVault(options =>");
        Console.WriteLine("    {");
        Console.WriteLine("        options.KeyIdentifier = new Uri(");
        Console.WriteLine("            \"https://my-vault.vault.azure.net/keys/proteos-kek/abcdef0123\");");
        Console.WriteLine("        // options.Credential defaults to DefaultAzureCredential when omitted.");
        Console.WriteLine("    });");
        Console.WriteLine();
        Console.WriteLine("This registers an AzureKeyVaultKeyProvider that wraps/unwraps the data keys with your");
        Console.WriteLine("Key Vault KEK. (The fluent '.UseAzureKeyVault(...)' form does not exist — the real");
        Console.WriteLine("entry point is AddProteosAzureKeyVault.)");

        return Task.CompletedTask;
    }
}
