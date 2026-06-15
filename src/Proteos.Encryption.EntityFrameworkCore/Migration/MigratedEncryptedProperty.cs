namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// The result of re-encrypting one property to the current key: the new stored value (a Base64
/// string for a string property, raw envelope bytes for a <c>byte[]</c> property) and, for a
/// searchable property, the recomputed blind index for its index column. A worker writes
/// <see cref="NewValue"/> to the property and, when present, <see cref="NewBlindIndex"/> to
/// <see cref="IndexPropertyName"/>.
/// </summary>
public sealed record MigratedEncryptedProperty(
    string PropertyName,
    object NewValue,
    string? IndexPropertyName,
    byte[]? NewBlindIndex)
{
    /// <summary>True when this property has a blind index column to update.</summary>
    public bool HasBlindIndex => IndexPropertyName is not null;
}
