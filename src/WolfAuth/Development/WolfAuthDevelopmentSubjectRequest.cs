namespace WolfAuth;

/// <summary>
/// Describes a normalized subject that should be created for local development, tests, or demos.
/// </summary>
public sealed record WolfAuthDevelopmentSubjectRequest
{
    /// <summary>
    /// Gets the provider-side user identifier.
    /// </summary>
    public required string ExternalUserId { get; init; }

    /// <summary>
    /// Gets the optional product-side subject identifier. When omitted, the external user id is used.
    /// </summary>
    public string? SubjectId { get; init; }

    /// <summary>
    /// Gets the development provider key.
    /// </summary>
    public WolfAuthProviderKey Provider { get; init; } = new("development");

    /// <summary>
    /// Gets the display name for UI and diagnostics.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the email address.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Gets the user principal name.
    /// </summary>
    public string? UserPrincipalName { get; init; }

    /// <summary>
    /// Gets external group identifiers to attach to the subject.
    /// </summary>
    public IReadOnlyList<string> GroupIds { get; init; } = [];

    /// <summary>
    /// Gets claims to attach to the subject.
    /// </summary>
    public IReadOnlyList<WolfAuthClaim> Claims { get; init; } = [];
}
