namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Thrown when a key cannot be resolved for the requested tenant and descriptor — for example
/// when the descriptor's key id does not belong to the tenant. The message names the key id (a
/// public identifier) but never any key material.
/// </summary>
public sealed class KeyResolutionException : ProteosEncryptionException
{
    public KeyResolutionException(string message)
        : base(message)
    {
    }
}
