namespace Proteos.Encryption.Abstractions;

/// <summary>
/// Describes an Additional Authenticated Data scheme: its registry id together with the
/// semantic distinction that justifies a separate scheme — whether the entity primary key is
/// part of the binding. This is the closed registry of schemes the abstraction recognises.
/// </summary>
public sealed record AadDescriptor
{
    /// <summary>The scheme's registry id, carried in the envelope header.</summary>
    public AadSchemeId SchemeId { get; }

    /// <summary>
    /// Whether the entity primary key is bound. Always false in the Foundation Release; the
    /// reserved context-bound scheme will set it true.
    /// </summary>
    public bool BindsEntityId { get; }

    private AadDescriptor(AadSchemeId schemeId, bool bindsEntityId)
    {
        SchemeId = schemeId;
        BindsEntityId = bindsEntityId;
    }

    /// <summary>The Foundation Release scheme: AAD is the envelope header; no entity-id binding.</summary>
    public static AadDescriptor HeaderBound { get; } = new(AadSchemeId.HeaderBound, bindsEntityId: false);
}
