namespace WolfAuth;

/// <summary>
/// Represents an idempotent subject provisioning request.
/// </summary>
public sealed record WolfAuthProvisioningRequest
{
    /// <summary>
    /// Gets the optional product-side subject identifier.
    /// </summary>
    public WolfAuthSubjectId? SubjectId { get; init; }

    /// <summary>
    /// Gets the identity provider that owns the external identity.
    /// </summary>
    public required WolfAuthProviderKey Provider { get; init; }

    /// <summary>
    /// Gets the provider-side user identifier.
    /// </summary>
    public required WolfAuthExternalUserId ExternalUserId { get; init; }

    /// <summary>
    /// Gets the display name to persist.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the email address to persist.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Gets the user principal name to persist.
    /// </summary>
    public string? UserPrincipalName { get; init; }

    /// <summary>
    /// Gets provider claims to persist with the subject snapshot.
    /// </summary>
    public IReadOnlyList<WolfAuthClaim> Claims { get; init; } = [];

    /// <summary>
    /// Gets external groups to persist with the subject snapshot.
    /// </summary>
    public IReadOnlyList<WolfAuthExternalGroup> Groups { get; init; } = [];

    /// <summary>
    /// Gets a value indicating whether the subject should remain active.
    /// </summary>
    public bool IsActive { get; init; } = true;
}
