namespace WolfAuth;

public sealed record WolfAuthEffectiveAccess
{
    public required WolfAuthSubject Subject { get; init; }

    public bool IsKnownSubject { get; init; }

    public IReadOnlyList<WolfAuthRoleKey> RoleKeys { get; init; } = [];

    public IReadOnlyList<WolfAuthPermissionGrant> Permissions { get; init; } = [];

    public IReadOnlyList<WolfAuthExternalGroup> ExternalGroups { get; init; } = [];

    public DateTimeOffset EvaluatedAt { get; init; } = DateTimeOffset.UtcNow;

    public bool HasPermission(WolfAuthPermissionKey permissionKey, WolfAuthScopeKey? scopeKey = null)
    {
        var requiredScope = scopeKey ?? WolfAuthScopeKey.Global;

        return Permissions.Any(permission =>
            permission.PermissionKey == permissionKey &&
            (permission.ScopeKey == WolfAuthScopeKey.Global || permission.ScopeKey == requiredScope));
    }
}
