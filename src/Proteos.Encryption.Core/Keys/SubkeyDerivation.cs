using System.Text;
using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.Core;

/// <summary>
/// The canonical working-key derivation shared by every key material provider: a per-purpose,
/// per-scope subkey <c>HKDF-SHA256(masterKey, info = purposeToken ‖ entityLogical ‖ propertyLogical)</c>,
/// with each <c>info</c> segment length-prefixed. Keeping it in one place means a development
/// provider and a registry/KMS provider derive identically and stay aligned with the specification.
/// </summary>
internal static class SubkeyDerivation
{
    /// <summary>Length in bytes of a derived working key (256-bit).</summary>
    public const int SubkeyLength = 32;

    /// <summary>Derives the working key for a purpose and scope from the (already resolved) master key.</summary>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The purpose is not a defined value.</exception>
    public static byte[] DeriveSubkey(ReadOnlySpan<byte> masterKey, KeyPurpose purpose, EncryptedDataScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return Hkdf.DeriveKey(masterKey, BuildInfo(PurposeToken(purpose), scope.Entity.Value, scope.Property.Value), SubkeyLength);
    }

    /// <summary>Builds a length-prefixed HKDF <c>info</c> from string segments.</summary>
    public static byte[] BuildInfo(params string[] segments)
    {
        var buffer = new List<byte>(64);
        foreach (var segment in segments)
        {
            AppendLengthPrefixed(buffer, segment);
        }

        return buffer.ToArray();
    }

    private static string PurposeToken(KeyPurpose purpose) => purpose switch
    {
        KeyPurpose.Encryption => "enc",
        KeyPurpose.BlindIndex => "idx",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown key purpose."),
    };

    private static void AppendLengthPrefixed(List<byte> buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Key derivation component exceeds the maximum length.", nameof(value));
        }

        buffer.Add((byte)(bytes.Length >> 8));
        buffer.Add((byte)bytes.Length);
        buffer.AddRange(bytes);
    }
}
