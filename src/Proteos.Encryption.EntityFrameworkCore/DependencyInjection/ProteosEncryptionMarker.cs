namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Sentinel registered by <c>AddProteosEncryption</c> so a second call can be detected and
/// rejected — the configuration must be unambiguous and applied exactly once.
/// </summary>
internal sealed class ProteosEncryptionMarker;
