using System.Text;
using Microsoft.Data.Sqlite;
using Proteos.Encryption.Abstractions;

namespace Proteos.FeatureShowcase.Infrastructure;

/// <summary>
/// Reads a column straight from the SQLite file with a plain ADO.NET query — bypassing EF and Proteos
/// entirely — to prove that what is stored on disk is a Proteos envelope, not plaintext.
/// </summary>
internal static class RawDatabaseInspector
{
    /// <summary>Reads the raw stored value of <paramref name="columnName"/> from the first row, or null.</summary>
    public static string? ReadRawColumn(string columnName, string table = "Customers")
    {
        using var connection = new SqliteConnection($"Data Source={ShowcaseHost.DatabaseFile}");
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {columnName} FROM {table} LIMIT 1";
        return command.ExecuteScalar() as string;
    }

    /// <summary>
    /// Prints the raw stored value of a string column and confirms it is a Proteos "PENC" envelope and
    /// not the given plaintext.
    /// </summary>
    public static void PrintRawValue(string columnName, string plaintextToLookFor)
    {
        var raw = ReadRawColumn(columnName);
        if (raw is null)
        {
            Console.WriteLine("Raw database value: (no rows)");
            return;
        }

        // String properties are stored as Base64 of the binary envelope; decode it to read the header.
        var envelope = Convert.FromBase64String(raw);
        var isEnvelope = CiphertextEnvelopeFormat.StartsWithMagic(envelope);
        var magic = Encoding.ASCII.GetString(envelope, 0, CiphertextEnvelopeFormat.MagicLength);

        Console.WriteLine("Raw database value:");
        Console.WriteLine($"  {Truncate(raw, 64)}");
        Console.WriteLine($"  decoded magic marker: \"{magic}\"  (Proteos envelope: {isEnvelope})");
        Console.WriteLine($"  contains plaintext \"{plaintextToLookFor}\"? {raw.Contains(plaintextToLookFor)}");
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "…";
}
