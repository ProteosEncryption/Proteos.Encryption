namespace Proteos.Encryption.GoogleCloudKms;

/// <summary>
/// A small, dependency-free CRC32C (Castagnoli) implementation used only to populate and verify the
/// integrity checksums that Cloud KMS exchanges on its encrypt/decrypt requests and responses. It is a
/// straightforward table-based software implementation — correctness over micro-optimisation — validated
/// against the standard CRC-32C check value (<c>"123456789"</c> → <c>0xE3069283</c>).
/// </summary>
internal static class Crc32C
{
    // Reflected Castagnoli polynomial (0x1EDC6F41 reversed).
    private const uint Polynomial = 0x82F63B78;

    private static readonly uint[] Table = BuildTable();

    /// <summary>Computes the CRC32C of <paramref name="data"/> as an unsigned 32-bit value.</summary>
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;

        foreach (var b in data)
        {
            crc = (crc >> 8) ^ Table[(crc ^ b) & 0xFF];
        }

        return crc ^ 0xFFFFFFFFu;
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];

        for (uint i = 0; i < table.Length; i++)
        {
            var crc = i;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ Polynomial : crc >> 1;
            }

            table[i] = crc;
        }

        return table;
    }
}
