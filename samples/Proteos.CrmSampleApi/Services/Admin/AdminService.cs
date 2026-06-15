using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Proteos.CrmSampleApi.Data;
using Proteos.CrmSampleApi.Dtos.Admin;
using Proteos.Encryption.Abstractions;
using Proteos.Encryption.Core;
using Proteos.Encryption.EntityFrameworkCore;

namespace Proteos.CrmSampleApi.Services.Admin;

public sealed class AdminService : IAdminService
{
    // The encrypted value columns to inspect (column name == property name). The list is hard-coded,
    // not user input, so interpolating it into SQL is safe.
    private static readonly (string Table, string Column)[] EncryptedColumns =
    {
        ("Customers", "CompanyName"), ("Customers", "BillingEmail"), ("Customers", "TaxNumber"),
        ("Contacts", "FullName"), ("Contacts", "Email"), ("Contacts", "Phone"),
        ("Addresses", "Street"), ("Addresses", "City"), ("Addresses", "PostalCode"),
        ("Orders", "Reference"), ("Orders", "InternalComment"),
        ("OrderNotes", "Text"),
    };

    // Known plaintext from the seed; none of it must ever appear in a stored (encrypted) value.
    private static readonly string[] KnownPlaintext =
    {
        "Alpha Cleaning", "Beta Facility", "billing@alpha", "billing@beta", "DE123456789", "DE987654321",
        "Max Mustermann", "Anna Müller", "Putzstraße", "Hausmeisterweg", "WINDOW-2026", "FLOOR-2026", "VIP customer",
    };

    private readonly CrmSampleDbContext _db;
    private readonly IEncryptionMigrationPlanner _planner;
    private readonly IKeyMaterialProvider _keyProvider;

    public AdminService(CrmSampleDbContext db, IEncryptionMigrationPlanner planner, IKeyMaterialProvider keyProvider)
    {
        _db = db;
        _planner = planner;
        _keyProvider = keyProvider;
    }

    public IReadOnlyList<EncryptionAuditResponse> GetAudit()
    {
        var report = _db.GetEncryptionAuditReport();
        return report.Entries
            .Select(entry => new EncryptionAuditResponse(entry.EntityClrType.Name, entry.PropertyName, entry.Classification.ToString()))
            .ToList();
    }

    public async Task<RawDatabasePreviewDto> GetRawPreviewAsync(CancellationToken ct)
    {
        await using var connection = new SqliteConnection(_db.Database.GetConnectionString());
        await connection.OpenAsync(ct);

        var previews = new List<RawColumnPreview>();
        var leak = false;

        foreach (var (table, column) in EncryptedColumns)
        {
            var values = await ReadColumnValuesAsync(connection, table, column, ct);
            if (values.Count == 0)
            {
                continue;
            }

            leak |= values.Any(value => KnownPlaintext.Any(plaintext => value.Contains(plaintext, StringComparison.OrdinalIgnoreCase)));
            previews.Add(new RawColumnPreview(table, column, Truncate(values[0], 24), IsEnvelope(values[0])));
        }

        var note = "Encrypted columns are stored as Base64 Proteos 'PENC' envelopes; previews are truncated. "
            + "PlaintextLeakDetected checks that no known seed plaintext appears in any stored value.";

        return new RawDatabasePreviewDto(note, leak, previews);
    }

    public async Task<ReEncryptionStatusDto> GetReEncryptionStatusAsync(CancellationToken ct)
    {
        var currentKeyId = _keyProvider.GetCurrentKeyId(new TenantId(CrmConstants.Tenant));

        await using var connection = new SqliteConnection(_db.Database.GetConnectionString());
        await connection.OpenAsync(ct);

        var scanned = 0;
        var needs = 0;
        foreach (var (table, column) in EncryptedColumns)
        {
            foreach (var value in await ReadColumnValuesAsync(connection, table, column, ct))
            {
                scanned++;
                if (_planner.NeedsReEncryption(typeof(string), value, currentKeyId))
                {
                    needs++;
                }
            }
        }

        var note = needs == 0
            ? "All encrypted values are under the current key (this sample uses a single-version dev key). "
              + "After a key rotation, values written under the old key would be counted here and migrated by a re-encrypt worker."
            : $"{needs} value(s) are under an older key and would be re-encrypted by a worker.";

        return new ReEncryptionStatusDto(Truncate(currentKeyId.ToString(), 16) + "…", scanned, needs, note);
    }

    private static async Task<List<string>> ReadColumnValuesAsync(SqliteConnection connection, string table, string column, CancellationToken ct)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT \"{column}\" FROM \"{table}\" WHERE \"{column}\" IS NOT NULL";

        var values = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!reader.IsDBNull(0))
            {
                values.Add(reader.GetString(0));
            }
        }

        return values;
    }

    private static bool IsEnvelope(string storedValue)
    {
        try
        {
            return CiphertextEnvelopeFormat.StartsWithMagic(Convert.FromBase64String(storedValue));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";
}
