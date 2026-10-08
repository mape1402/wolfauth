namespace WolfAuth;

/// <summary>
/// Represents a normalized claim issued by an external identity provider.
/// </summary>
public sealed record WolfAuthClaim
{
    /// <summary>
    /// Gets the claim type.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Gets the claim value.
    /// </summary>
    public string? Value { get; init; }

    /// <summary>
    /// Gets the claim issuer when it is known.
    /// </summary>
    public string? Issuer { get; init; }
}

/// <summary>
/// Represents an external group observed on the authenticated subject.
/// </summary>
public sealed record WolfAuthExternalGroup
{
    /// <summary>
    /// Gets the provider that owns the external group.
    /// </summary>
    public required WolfAuthProviderKey Provider { get; init; }

    /// <summary>
    /// Gets the provider-side group identifier.
    /// </summary>
    public required WolfAuthExternalGroupKey ExternalGroupId { get; init; }

    /// <summary>
    /// Gets the human-readable group name when it is available.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets provider-specific metadata associated with the group.
    /// </summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Represents the normalized authenticated identity passed into WolfAuth authorization.
/// </summary>
public sealed record WolfAuthSubject
{
    /// <summary>
    /// Gets the stable subject identifier used by the host product.
    /// </summary>
    public required WolfAuthSubjectId SubjectId { get; init; }

    /// <summary>
    /// Gets the external identity provider that authenticated the subject.
    /// </summary>
    public required WolfAuthProviderKey Provider { get; init; }

    /// <summary>
    /// Gets the provider-side user identifier.
    /// </summary>
    public required WolfAuthExternalUserId ExternalUserId { get; init; }

    /// <summary>
    /// Gets the display name for UI and diagnostics.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the email address when it is available.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Gets the user principal name when it is available.
    /// </summary>
    public string? UserPrincipalName { get; init; }

    /// <summary>
    /// Gets normalized claims carried by the authenticated identity.
    /// </summary>
    public IReadOnlyList<WolfAuthClaim> Claims { get; init; } = [];

    /// <summary>
    /// Gets external groups carried by or resolved for the authenticated identity.
    /// </summary>
    public IReadOnlyList<WolfAuthExternalGroup> Groups { get; init; } = [];
}
