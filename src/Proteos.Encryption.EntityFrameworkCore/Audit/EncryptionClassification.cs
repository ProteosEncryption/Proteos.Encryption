namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>How a string or <c>byte[]</c> property is classified in the encryption audit.</summary>
public enum EncryptionClassification
{
    /// <summary>Stored encrypted (<c>[Encrypted]</c> / <c>.IsEncrypted(...)</c>).</summary>
    Encrypted,

    /// <summary>Stored encrypted and searchable via a blind index (<c>[EncryptedSearchable]</c> / <c>[EncryptedEmail]</c>).</summary>
    EncryptedSearchable,

    /// <summary>Deliberately stored in plaintext (<c>[Plaintext]</c> / <c>.IsPlaintext()</c>).</summary>
    Plaintext,

    /// <summary>Neither encrypted nor explicitly plaintext — a strict-mode violation.</summary>
    Unclassified,
}
