namespace WolfAuth;

public enum WolfAuthPermissionRiskLevel
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

public sealed record WolfAuthPermission
{
    public required WolfAuthPermissionKey Key { get; init; }

    public string? DisplayName { get; init; }

    public string? Description { get; init; }

    public string? Category { get; init; }

    public WolfAuthPermissionRiskLevel RiskLevel { get; init; } = WolfAuthPermissionRiskLevel.Low;

    public IReadOnlyList<string> Tags { get; init; } = [];
}

public enum WolfAuthGrantSource
{
    Direct = 0,
    Role = 1,
    ExternalGroup = 2,
    Bootstrap = 3,
    Default = 4
}

public sealed record WolfAuthPermissionGrant
{
    public required WolfAuthPermissionKey PermissionKey { get; init; }

    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    public WolfAuthGrantSource Source { get; init; } = WolfAuthGrantSource.Direct;

    public WolfAuthRoleKey? RoleKey { get; init; }

    public WolfAuthExternalGroupKey? ExternalGroupKey { get; init; }
}
