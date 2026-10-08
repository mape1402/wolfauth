namespace WolfAuth;

public enum WolfAuthAssignmentTargetKind
{
    Subject = 0,
    ExternalGroup = 1,
    DefaultAuthenticatedSubject = 2,
    BootstrapAdministrator = 3
}

public enum WolfAuthAssignmentGrantKind
{
    Permission = 0,
    Role = 1
}

public sealed record WolfAuthAssignment
{
    public required string AssignmentId { get; init; }

    public required WolfAuthAssignmentTargetKind TargetKind { get; init; }

    public WolfAuthSubjectId? SubjectId { get; init; }

    public WolfAuthExternalGroupKey? ExternalGroupKey { get; init; }

    public required WolfAuthAssignmentGrantKind GrantKind { get; init; }

    public WolfAuthPermissionKey? PermissionKey { get; init; }

    public WolfAuthRoleKey? RoleKey { get; init; }

    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    public string? Source { get; init; }
}
