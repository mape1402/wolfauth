namespace WolfAuth;

/// <summary>
/// Identifies the type of principal or seed source targeted by an assignment.
/// </summary>
public enum WolfAuthAssignmentTargetKind
{
    /// <summary>
    /// The assignment targets a known subject.
    /// </summary>
    Subject = 0,

    /// <summary>
    /// The assignment targets an external group mapping.
    /// </summary>
    ExternalGroup = 1,

    /// <summary>
    /// The assignment targets any authenticated subject when open access is enabled.
    /// </summary>
    DefaultAuthenticatedSubject = 2,

    /// <summary>
    /// The assignment targets bootstrap administrator seeding.
    /// </summary>
    BootstrapAdministrator = 3
}

/// <summary>
/// Identifies the kind of access granted by an assignment.
/// </summary>
public enum WolfAuthAssignmentGrantKind
{
    /// <summary>
    /// The assignment grants a permission directly.
    /// </summary>
    Permission = 0,

    /// <summary>
    /// The assignment grants a role.
    /// </summary>
    Role = 1
}

/// <summary>
/// Represents a durable grant instruction for a subject, group, default access rule, or bootstrap administrator.
/// </summary>
public sealed record WolfAuthAssignment
{
    /// <summary>
    /// Gets the assignment identifier.
    /// </summary>
    public required string AssignmentId { get; init; }

    /// <summary>
    /// Gets the target kind for the assignment.
    /// </summary>
    public required WolfAuthAssignmentTargetKind TargetKind { get; init; }

    /// <summary>
    /// Gets the subject identifier when the assignment targets a subject.
    /// </summary>
    public WolfAuthSubjectId? SubjectId { get; init; }

    /// <summary>
    /// Gets the external group key when the assignment targets a group mapping.
    /// </summary>
    public WolfAuthExternalGroupKey? ExternalGroupKey { get; init; }

    /// <summary>
    /// Gets whether the assignment grants a permission or role.
    /// </summary>
    public required WolfAuthAssignmentGrantKind GrantKind { get; init; }

    /// <summary>
    /// Gets the permission key when the assignment grants a permission.
    /// </summary>
    public WolfAuthPermissionKey? PermissionKey { get; init; }

    /// <summary>
    /// Gets the role key when the assignment grants a role.
    /// </summary>
    public WolfAuthRoleKey? RoleKey { get; init; }

    /// <summary>
    /// Gets the scope where the assignment applies.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    /// <summary>
    /// Gets an optional source label for diagnostics and future audit records.
    /// </summary>
    public string? Source { get; init; }
}
