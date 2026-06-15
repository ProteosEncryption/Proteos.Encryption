namespace Proteos.Encryption.Abstractions;

/// <summary>
/// The complete derivation address of a subkey: which master key (<see cref="KeyId"/>), for
/// which purpose (encryption vs. blind index) and within which logical scope. The crypto core
/// turns it into an HKDF derivation; selecting the master key by <see cref="KeyId"/> and binding
/// purpose and scope into <c>info</c> is what enforces domain separation and scope binding.
/// </summary>
public sealed record KeyDescriptor
{
    /// <summary>Opaque identifier of the master key the subkey is derived from.</summary>
    public KeyId KeyId { get; }

    /// <summary>The purpose that separates this subkey from others of the same master key.</summary>
    public KeyPurpose Purpose { get; }

    /// <summary>The logical entity/property scope bound into the derivation.</summary>
    public EncryptedDataScope Scope { get; }

    /// <summary>Creates a key descriptor.</summary>
    /// <exception cref="ArgumentNullException">Key id or scope is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Purpose is not a defined value.</exception>
    public KeyDescriptor(KeyId keyId, KeyPurpose purpose, EncryptedDataScope scope)
    {
        KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));

        if (!Enum.IsDefined(purpose))
        {
            throw new ArgumentOutOfRangeException(nameof(purpose), purpose, "Unknown key purpose.");
        }

        Purpose = purpose;
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
    }
}
