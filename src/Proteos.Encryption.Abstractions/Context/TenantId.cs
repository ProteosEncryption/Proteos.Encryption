namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Identifies a tenant — an organisation, company or mandate context, <b>not</b> an end user.
/// A tenant is the unit of key isolation: it selects the Tenant Master Key, and therefore
/// ciphertext of one tenant is not decryptable with another tenant's key.
/// </summary>
public sealed record TenantId
{
    /// <summary>The normalised (trimmed) tenant identifier.</summary>
    public string Value { get; }

    /// <summary>Creates a tenant identifier. Surrounding whitespace is trimmed.</summary>
    /// <exception cref="ArgumentException">The value is null, empty or whitespace.</exception>
    public TenantId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Tenant id must be a non-empty, non-whitespace value.", nameof(value));
        }

        Value = value.Trim();
    }

    public override string ToString() => Value;
}
