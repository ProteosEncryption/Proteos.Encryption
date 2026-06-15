using Proteos.Encryption.Abstractions;

namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// Validated metadata for one encrypted property: which CLR property, its type and logical name,
/// the resolved <see cref="EncryptedDataScope"/> (entity + property logical names), and — when
/// searchable — the blind index property and its normalizer. <see cref="IndexIsShadow"/> tells the
/// model convention whether to create an EF shadow property or use an existing CLR property.
/// </summary>
public sealed record EncryptedPropertyDescriptor(
    string PropertyName,
    Type PropertyType,
    string PropertyLogicalName,
    EncryptedDataScope Scope,
    bool IsSearchable,
    string? IndexPropertyName,
    bool IndexIsShadow,
    BlindIndexNormalizerKind? NormalizerKind);
