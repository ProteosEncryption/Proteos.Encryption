using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// AWS KMS setup — example only. No secrets, nothing is called. Shows the real registration API.
/// </summary>
public sealed class Scenario09_AwsSetupExample : IScenario
{
    public string Title => "AWS KMS setup";

    public Task ExecuteAsync()
    {
        // ---------------------------------------------------------------------------------------
        // Example only. This code is NOT executed here — it needs real AWS credentials and a KMS key.
        //
        //   // Add the package: Proteos.Encryption.AwsKms
        //
        //   services.AddProteosAwsKms(options =>
        //   {
        //       options.KeyId = "arn:aws:kms:eu-central-1:111122223333:key/abcd1234-...";
        //       options.Region = "eu-central-1"; // optional when the key reference is an ARN
        //   });
        //
        // Credentials always come from the AWS SDK's default credential chain. The rest of the wiring
        // is identical to the development setup used by the other scenarios.
        // ---------------------------------------------------------------------------------------

        Console.WriteLine("Example only — no real secrets, nothing is called.");
        Console.WriteLine();
        Console.WriteLine("Add the package:  Proteos.Encryption.AwsKms");
        Console.WriteLine();
        Console.WriteLine("    services.AddProteosAwsKms(options =>");
        Console.WriteLine("    {");
        Console.WriteLine("        options.KeyId = \"arn:aws:kms:eu-central-1:111122223333:key/abcd1234-...\";");
        Console.WriteLine("        options.Region = \"eu-central-1\"; // optional when the key reference is an ARN");
        Console.WriteLine("    });");
        Console.WriteLine();
        Console.WriteLine("This registers an AwsKmsKeyProvider that wraps/unwraps the data keys with your KMS key.");
        Console.WriteLine("Credentials come from the AWS SDK default chain; none is hard-coded.");

        return Task.CompletedTask;
    }
}
