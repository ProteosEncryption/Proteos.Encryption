using System.Text;
using Proteos.Encryption.GoogleCloudKms;
using Xunit;

namespace Proteos.Encryption.GoogleCloudKms.Tests;

public sealed class Crc32CTests
{
    [Fact]
    public void Compute_StandardCheckString_MatchesKnownVector()
    {
        // The canonical CRC-32C (Castagnoli) check value for "123456789".
        var data = Encoding.ASCII.GetBytes("123456789");

        Assert.Equal(0xE3069283u, Crc32C.Compute(data));
    }

    [Fact]
    public void Compute_Empty_IsZero()
    {
        Assert.Equal(0u, Crc32C.Compute(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Compute_IsDeterministic()
    {
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F };

        Assert.Equal(Crc32C.Compute(data), Crc32C.Compute(data));
    }
}
