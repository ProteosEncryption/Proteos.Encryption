using Proteos.Encryption.Abstractions;
using Xunit;

namespace Proteos.Encryption.Abstractions.Tests;

public sealed class BlindIndexPurposeTests
{
    [Fact]
    public void Defines_ExactMatch()
    {
        Assert.True(Enum.IsDefined(BlindIndexPurpose.ExactMatch));
    }
}

public sealed class BlindIndexDescriptorTests
{
    [Fact]
    public void Constructor_WithValidPurpose_Succeeds()
    {
        var descriptor = new BlindIndexDescriptor(BlindIndexPurpose.ExactMatch);

        Assert.Equal(BlindIndexPurpose.ExactMatch, descriptor.Purpose);
    }

    [Fact]
    public void Constructor_WithUndefinedPurpose_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BlindIndexDescriptor((BlindIndexPurpose)99));
    }

    [Fact]
    public void ExactMatch_IsValueEqualToConstructed()
    {
        Assert.Equal(new BlindIndexDescriptor(BlindIndexPurpose.ExactMatch), BlindIndexDescriptor.ExactMatch);
    }
}

public sealed class BlindIndexValueTests
{
    [Fact]
    public void Create_WithValidBytes_Succeeds()
    {
        var value = BlindIndexValue.Create([1, 2, 3]);

        Assert.Equal(3, value.Length);
        Assert.Equal(new byte[] { 1, 2, 3 }, value.ToArray());
    }

    [Fact]
    public void Create_WithEmptyInput_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => BlindIndexValue.Create(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Create_CopiesInput_SoLaterMutationDoesNotLeak()
    {
        var source = new byte[] { 1, 2, 3 };
        var value = BlindIndexValue.Create(source);

        source[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2, 3 }, value.ToArray());
    }

    [Fact]
    public void ToArray_ReturnsDefensiveCopy()
    {
        var value = BlindIndexValue.Create([1, 2, 3]);

        var copy = value.ToArray();
        copy[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2, 3 }, value.ToArray());
    }

    [Fact]
    public void Equality_IsContentBased()
    {
        var a = BlindIndexValue.Create([1, 2, 3]);
        var b = BlindIndexValue.Create([1, 2, 3]);

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Equality_DistinguishesDifferentContent()
    {
        var a = BlindIndexValue.Create([1, 2, 3]);
        var b = BlindIndexValue.Create([1, 2, 4]);

        Assert.NotEqual(a, b);
        Assert.True(a != b);
    }

    [Fact]
    public void ToString_IsHex()
    {
        Assert.Equal("010203", BlindIndexValue.Create([1, 2, 3]).ToString());
    }
}
