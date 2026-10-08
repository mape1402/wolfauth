namespace WolfAuth;

public enum WolfAuthEvaluationReason
{
    Allowed = 0,
    AllowedByDirectPermission = 1,
    AllowedByRole = 2,
    AllowedByExternalGroup = 3,
    AllowedByBootstrapAdministrator = 4,
    AllowedByDefaultRole = 5,
    DeniedUnknownSubject = 100,
    DeniedMissingPermission = 101,
    DeniedScopeMismatch = 102,
    DeniedUnknownPermission = 103,
    DeniedPolicyNotRegistered = 104,
    DeniedPolicyFailed = 105,
    DeniedInvalidRequest = 106
}

public sealed record WolfAuthEvaluationResult
{
    public required bool IsAllowed { get; init; }

    public required WolfAuthEvaluationReason Reason { get; init; }

    public string? Message { get; init; }

    public WolfAuthPermissionKey? PermissionKey { get; init; }

    public WolfAuthPolicyKey? PolicyKey { get; init; }

    public WolfAuthRoleKey? RoleKey { get; init; }

    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    public WolfAuthEffectiveAccess? EffectiveAccess { get; init; }

    public IReadOnlyList<string> Diagnostics { get; init; } = [];

    public static WolfAuthEvaluationResult Allow(
        WolfAuthEvaluationReason reason,
        WolfAuthScopeKey? scopeKey = null,
        WolfAuthPermissionKey? permissionKey = null,
        WolfAuthPolicyKey? policyKey = null,
        WolfAuthRoleKey? roleKey = null,
        WolfAuthEffectiveAccess? effectiveAccess = null)
    {
        return new WolfAuthEvaluationResult
        {
            IsAllowed = true,
            Reason = reason,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global,
            PermissionKey = permissionKey,
            PolicyKey = policyKey,
            RoleKey = roleKey,
            EffectiveAccess = effectiveAccess
        };
    }

    public static WolfAuthEvaluationResult Deny(
        WolfAuthEvaluationReason reason,
        string? message = null,
        WolfAuthScopeKey? scopeKey = null,
        WolfAuthPermissionKey? permissionKey = null,
        WolfAuthPolicyKey? policyKey = null)
    {
        return new WolfAuthEvaluationResult
        {
            IsAllowed = false,
            Reason = reason,
            Message = message,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global,
            PermissionKey = permissionKey,
            PolicyKey = policyKey
        };
    }
}
