namespace Proteos.Encryption.EntityFrameworkCore;

/// <summary>
/// The source-agnostic encryption intent of a single property: its logical name, whether it is
/// searchable, the blind index normalizer and an optional explicit index property. Attributes and
/// the fluent API both produce this same record, which is then turned into an
/// <see cref="EncryptedPropertyDescriptor"/> by the shared metadata factory — so neither source has
/// its own validation or descriptor logic. Being a record, two configurations are value-equal,
/// which is how an attribute and a fluent configuration of the same property are detected as
/// identical (allowed) or conflicting (rejected).
/// </summary>
internal sealed record EncryptedPropertyConfiguration(
    string PropertyLogicalName,
    bool IsSearchable,
    BlindIndexNormalizerKind? Normalizer,
    string? ExplicitIndexProperty);
