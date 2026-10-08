namespace WolfAuth.EntityFrameworkCore;

/// <summary>
/// Represents a persisted WolfAuth subject entity.
/// </summary>
public sealed class WolfAuthSubjectEntity
{
    /// <summary>
    /// Gets or sets the subject identifier.
    /// </summary>
    public string SubjectId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the provider key.
    /// </summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the provider-side user identifier.
    /// </summary>
    public string ExternalUserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the display name.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the email address.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// Gets or sets the user principal name.
    /// </summary>
    public string? UserPrincipalName { get; set; }

    /// <summary>
    /// Gets or sets serialized claims.
    /// </summary>
    public string ClaimsJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets serialized external groups.
    /// </summary>
    public string GroupsJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets a value indicating whether the subject is active.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Gets or sets the timestamp when the subject was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Gets or sets the timestamp when the subject was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
