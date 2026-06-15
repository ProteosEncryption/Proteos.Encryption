namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Base type for operational failures raised by Proteos encryption (for example envelope
/// parsing, authentication or key resolution). It is the stable root that more specific
/// exceptions derive from as the implementing components are added; the abstractions themselves
/// validate their inputs with the standard <see cref="ArgumentException"/> family.
/// </summary>
public class ProteosEncryptionException : Exception
{
    public ProteosEncryptionException(string message)
        : base(message)
    {
    }

    public ProteosEncryptionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
