using Proteos.Encryption.Abstractions;
using Xunit;

namespace Proteos.Encryption.Abstractions.Tests;

public sealed class KeyIdTests
{
    [Fact]
    public void FromBytes_WithValidLength_CreatesIdentifier()
    {
        var id = KeyId.FromBytes([1, 2, 3]);

        Assert.Equal(3, id.Length);
        Assert.Equal(new byte[] { 1, 2, 3 }, id.ToArray());
    }

    [Fact]
    public void FromBytes_WithEmptyInput_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyId.FromBytes(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void FromBytes_AboveMaxLength_IsRejected()
    {
        var tooLong = new byte[KeyId.MaxLength + 1];

        Assert.Throws<ArgumentOutOfRangeException>(() => KeyId.FromBytes(tooLong));
    }

    [Fact]
    public void FromBytes_AtMaxLength_IsAccepted()
    {
        var id = KeyId.FromBytes(new byte[KeyId.MaxLength]);

        Assert.Equal(KeyId.MaxLength, id.Length);
    }

    [Fact]
    public void FromBytes_CopiesInput_SoLaterMutationDoesNotLeak()
    {
        var source = new byte[] { 1, 2, 3 };
        var id = KeyId.FromBytes(source);

        source[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2, 3 }, id.ToArray());
    }

    [Fact]
    public void ToArray_ReturnsDefensiveCopy()
    {
        var id = KeyId.FromBytes([1, 2, 3]);

        var copy = id.ToArray();
        copy[0] = 0xFF;

        Assert.Equal(new byte[] { 1, 2, 3 }, id.ToArray());
    }

    [Fact]
    public void Equality_IsContentBased()
    {
        var a = KeyId.FromBytes([1, 2, 3]);
        var b = KeyId.FromBytes([1, 2, 3]);

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.False(a != b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void Equality_DistinguishesDifferentContent()
    {
        var a = KeyId.FromBytes([1, 2, 3]);
        var b = KeyId.FromBytes([1, 2, 4]);

        Assert.NotEqual(a, b);
        Assert.True(a != b);
    }

    [Fact]
    public void ToString_IsHex()
    {
        var id = KeyId.FromBytes([0x0A, 0xFF]);

        Assert.Equal("0AFF", id.ToString());
    }
}

public sealed class KeyDescriptorTests
{
    private static EncryptedDataScope Scope() =>
        new(new LogicalName("Customer"), new LogicalName("Email"));

    [Fact]
    public void Constructor_WithValidArguments_Succeeds()
    {
        var descriptor = new KeyDescriptor(KeyId.FromBytes([1]), KeyPurpose.Encryption, Scope());

        Assert.Equal(KeyPurpose.Encryption, descriptor.Purpose);
    }

    [Fact]
    public void Constructor_WithNullKeyId_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new KeyDescriptor(null!, KeyPurpose.Encryption, Scope()));
    }

    [Fact]
    public void Constructor_WithNullScope_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new KeyDescriptor(KeyId.FromBytes([1]), KeyPurpose.Encryption, null!));
    }

    [Fact]
    public void Constructor_WithUndefinedPurpose_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyDescriptor(KeyId.FromBytes([1]), (KeyPurpose)99, Scope()));
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        var a = new KeyDescriptor(KeyId.FromBytes([1]), KeyPurpose.Encryption, Scope());
        var b = new KeyDescriptor(KeyId.FromBytes([1]), KeyPurpose.Encryption, Scope());

        Assert.Equal(a, b);
    }

    [Fact]
    public void Equality_DistinguishesPurpose()
    {
        var enc = new KeyDescriptor(KeyId.FromBytes([1]), KeyPurpose.Encryption, Scope());
        var idx = new KeyDescriptor(KeyId.FromBytes([1]), KeyPurpose.BlindIndex, Scope());

        Assert.NotEqual(enc, idx);
    }
}

public sealed class WrappedKeyTests
{
    [Fact]
    public void Create_WithValidArguments_Succeeds()
    {
        var wrapped = WrappedKey.Create(KeyId.FromBytes([1]), [9, 8, 7]);

        Assert.Equal(new byte[] { 9, 8, 7 }, wrapped.ToArray());
    }

    [Fact]
    public void Create_WithNullKeyId_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => WrappedKey.Create(null!, [1]));
    }

    [Fact]
    public void Create_WithEmptyCiphertext_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => WrappedKey.Create(KeyId.FromBytes([1]), ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Create_CopiesInput_SoLaterMutationDoesNotLeak()
    {
        var source = new byte[] { 9, 8, 7 };
        var wrapped = WrappedKey.Create(KeyId.FromBytes([1]), source);

        source[0] = 0xFF;

        Assert.Equal(new byte[] { 9, 8, 7 }, wrapped.ToArray());
    }

    [Fact]
    public void Equality_ConsidersKeyIdAndCiphertext()
    {
        var a = WrappedKey.Create(KeyId.FromBytes([1]), [9, 8, 7]);
        var b = WrappedKey.Create(KeyId.FromBytes([1]), [9, 8, 7]);
        var differentKey = WrappedKey.Create(KeyId.FromBytes([2]), [9, 8, 7]);
        var differentCipher = WrappedKey.Create(KeyId.FromBytes([1]), [9, 8, 6]);

        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.NotEqual(a, differentKey);
        Assert.NotEqual(a, differentCipher);
    }
}

public sealed class KeyPurposeTests
{
    [Fact]
    public void Defines_EncryptionAndBlindIndex()
    {
        Assert.True(Enum.IsDefined(KeyPurpose.Encryption));
        Assert.True(Enum.IsDefined(KeyPurpose.BlindIndex));
        Assert.NotEqual(KeyPurpose.Encryption, KeyPurpose.BlindIndex);
    }
}
