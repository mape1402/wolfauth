namespace WolfAuth.EntityFrameworkCore;

/// <summary>
/// Represents a persisted WolfAuth assignment entity.
/// </summary>
public sealed class WolfAuthAssignmentEntity
{
    /// <summary>
    /// Gets or sets the assignment identifier.
    /// </summary>
    public string AssignmentId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the assignment target kind.
    /// </summary>
    public int TargetKind { get; set; }

    /// <summary>
    /// Gets or sets the subject identifier.
    /// </summary>
    public string? SubjectId { get; set; }

    /// <summary>
    /// Gets or sets the external group key.
    /// </summary>
    public string? ExternalGroupKey { get; set; }

    /// <summary>
    /// Gets or sets the assignment grant kind.
    /// </summary>
    public int GrantKind { get; set; }

    /// <summary>
    /// Gets or sets the permission key.
    /// </summary>
    public string? PermissionKey { get; set; }

    /// <summary>
    /// Gets or sets the role key.
    /// </summary>
    public string? RoleKey { get; set; }

    /// <summary>
    /// Gets or sets the scope key.
    /// </summary>
    public string ScopeKey { get; set; } = WolfAuthScopeKey.Global.ToString();

    /// <summary>
    /// Gets or sets the optional source label.
    /// </summary>
    public string? Source { get; set; }
}
