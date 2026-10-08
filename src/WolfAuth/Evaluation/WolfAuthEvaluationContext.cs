namespace WolfAuth;

public enum WolfAuthEvaluationKind
{
    Permission = 0,
    Policy = 1
}

public sealed record WolfAuthEvaluationContext
{
    public required WolfAuthSubject Subject { get; init; }

    public required WolfAuthEvaluationKind Kind { get; init; }

    public WolfAuthPermissionKey? PermissionKey { get; init; }

    public WolfAuthPolicyKey? PolicyKey { get; init; }

    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    public object? Resource { get; init; }

    public IReadOnlyDictionary<string, object?> Items { get; init; } = new Dictionary<string, object?>();

    public static WolfAuthEvaluationContext ForPermission(
        WolfAuthSubject subject,
        WolfAuthPermissionKey permissionKey,
        WolfAuthScopeKey? scopeKey = null,
        object? resource = null)
    {
        return new WolfAuthEvaluationContext
        {
            Subject = subject,
            Kind = WolfAuthEvaluationKind.Permission,
            PermissionKey = permissionKey,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global,
            Resource = resource
        };
    }

    public static WolfAuthEvaluationContext ForPolicy(
        WolfAuthSubject subject,
        WolfAuthPolicyKey policyKey,
        WolfAuthScopeKey? scopeKey = null,
        object? resource = null)
    {
        return new WolfAuthEvaluationContext
        {
            Subject = subject,
            Kind = WolfAuthEvaluationKind.Policy,
            PolicyKey = policyKey,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global,
            Resource = resource
        };
    }
}
