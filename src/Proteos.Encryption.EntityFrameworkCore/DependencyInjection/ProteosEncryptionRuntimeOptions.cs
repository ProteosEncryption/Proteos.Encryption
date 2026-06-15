namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Runtime-relevant options captured from <see cref="ProteosEncryptionOptions"/> at registration and
/// exposed as a singleton, so the save interceptor can read them without re-parsing configuration.
/// Currently just the strict-mode flag.
/// </summary>
internal sealed class ProteosEncryptionRuntimeOptions
{
    public ProteosEncryptionRuntimeOptions(bool strictMode) => StrictMode = strictMode;

    /// <summary>When true, the save interceptor rejects unclassified string/byte[] properties.</summary>
    public bool StrictMode { get; }
}
