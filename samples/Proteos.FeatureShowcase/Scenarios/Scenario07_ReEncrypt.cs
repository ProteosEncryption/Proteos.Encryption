using Microsoft.Extensions.DependencyInjection;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;
using Proteos.FeatureShowcase.Infrastructure;

namespace Proteos.FeatureShowcase.Scenarios;

/// <summary>
/// The re-encryption foundation. After a key rotation, the planner detects — by reading the envelope
/// HEADER only, no decryption — which stored values are still under an older key and need
/// re-encryption. The full migration (decrypt → encrypt under the current key → reindex → persist) is
/// only described here, not performed.
/// </summary>
public sealed class Scenario07_ReEncrypt : IScenario
{
    public string Title => "ReEncrypt/ReIndex";

    public async Task ExecuteAsync()
    {
        // Save a row while the current key is v1.
        using (var sp = ShowcaseHost.Build(ShowcaseHost.Rotating(currentVersion: 1)))
        using (var scope = sp.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ShowcaseDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
            db.Customers.Add(new Customer { Email = "legacy@example.com", Name = "Legacy Row", Phone = "+49 1" });
            await db.SaveChangesAsync();
        }

        // The current key is now v2. Ask the planner whether the stored v1 value needs re-encryption.
        using (var sp = ShowcaseHost.Build(ShowcaseHost.Rotating(currentVersion: 2)))
        using (var scope = sp.CreateScope())
        {
            var planner = scope.ServiceProvider.GetRequiredService<IEncryptionMigrationPlanner>();
            var keyProvider = scope.ServiceProvider.GetRequiredService<IKeyMaterialProvider>();
            var currentKeyId = keyProvider.GetCurrentKeyId(new TenantId(ShowcaseHost.Tenant));

            var storedEmail = RawDatabaseInspector.ReadRawColumn("Email"); // Base64 envelope, no decryption
            var storedKeyId = planner.ReadStoredKeyId(typeof(string), storedEmail);
            var needs = planner.NeedsReEncryption(typeof(string), storedEmail, currentKeyId);

            Console.WriteLine($"Stored under key id : {storedKeyId}");
            Console.WriteLine($"Current key id      : {currentKeyId}");
            Console.WriteLine($"NeedsReEncryption    : {needs}");
        }

        Console.WriteLine();
        Console.WriteLine("A re-encrypt worker would then, per stored value, call");
        Console.WriteLine("IEncryptionMigrationService.ReEncrypt(...) (decrypt -> encrypt under the current key");
        Console.WriteLine("-> recompute the blind index) and persist the result. The batch foundation");
        Console.WriteLine("(ReEncryptBatchOptions / ReEncryptProgress / ReEncryptResumeToken) exists for that;");
        Console.WriteLine("this showcase demonstrates only the read-only detection, not a full migration.");
    }
}
