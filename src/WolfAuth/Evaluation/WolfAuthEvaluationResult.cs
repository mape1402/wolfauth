namespace WolfAuth;

/// <summary>
/// Provides stable reason codes for authorization outcomes.
/// </summary>
public enum WolfAuthEvaluationReason
{
    /// <summary>
    /// The request was allowed without a more specific reason.
    /// </summary>
    Allowed = 0,

    /// <summary>
    /// The request was allowed by a direct permission assignment.
    /// </summary>
    AllowedByDirectPermission = 1,

    /// <summary>
    /// The request was allowed by an internal role.
    /// </summary>
    AllowedByRole = 2,

    /// <summary>
    /// The request was allowed by an external group mapping.
    /// </summary>
    AllowedByExternalGroup = 3,

    /// <summary>
    /// The request was allowed by bootstrap administrator access.
    /// </summary>
    AllowedByBootstrapAdministrator = 4,

    /// <summary>
    /// The request was allowed by default authenticated access.
    /// </summary>
    AllowedByDefaultRole = 5,

    /// <summary>
    /// The request was denied because the subject is not provisioned and known subjects are required.
    /// </summary>
    DeniedUnknownSubject = 100,

    /// <summary>
    /// The request was denied because no matching permission grant was found.
    /// </summary>
    DeniedMissingPermission = 101,

    /// <summary>
    /// The request was denied because available grants did not match the requested scope.
    /// </summary>
    DeniedScopeMismatch = 102,

    /// <summary>
    /// The request was denied because the requested permission is not registered by the host.
    /// </summary>
    DeniedUnknownPermission = 103,

    /// <summary>
    /// The request was denied because the requested policy is not registered by the host.
    /// </summary>
    DeniedPolicyNotRegistered = 104,

    /// <summary>
    /// The request was denied because the registered policy did not pass.
    /// </summary>
    DeniedPolicyFailed = 105,

    /// <summary>
    /// The request was denied because the evaluation context was invalid.
    /// </summary>
    DeniedInvalidRequest = 106
}

/// <summary>
/// Represents the result of a WolfAuth authorization evaluation.
/// </summary>
public sealed record WolfAuthEvaluationResult
{
    /// <summary>
    /// Gets a value indicating whether the request is allowed.
    /// </summary>
    public required bool IsAllowed { get; init; }

    /// <summary>
    /// Gets the stable reason code for the outcome.
    /// </summary>
    public required WolfAuthEvaluationReason Reason { get; init; }

    /// <summary>
    /// Gets an optional human-readable message for diagnostics or UI hints.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Gets the permission key involved in the evaluation when applicable.
    /// </summary>
    public WolfAuthPermissionKey? PermissionKey { get; init; }

    /// <summary>
    /// Gets the policy key involved in the evaluation when applicable.
    /// </summary>
    public WolfAuthPolicyKey? PolicyKey { get; init; }

    /// <summary>
    /// Gets the role key that allowed the request when applicable.
    /// </summary>
    public WolfAuthRoleKey? RoleKey { get; init; }

    /// <summary>
    /// Gets the scope involved in the evaluation.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    /// <summary>
    /// Gets the effective access snapshot used for the evaluation when available.
    /// </summary>
    public WolfAuthEffectiveAccess? EffectiveAccess { get; init; }

    /// <summary>
    /// Gets diagnostic messages produced during evaluation.
    /// </summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = [];

    /// <summary>
    /// Creates an allowed evaluation result.
    /// </summary>
    /// <param name="reason">The stable reason code.</param>
    /// <param name="scopeKey">The scope involved in the evaluation.</param>
    /// <param name="permissionKey">The permission key involved in the evaluation.</param>
    /// <param name="policyKey">The policy key involved in the evaluation.</param>
    /// <param name="roleKey">The role key that allowed the request.</param>
    /// <param name="effectiveAccess">The effective access snapshot used by the evaluation.</param>
    /// <returns>An allowed evaluation result.</returns>
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

    /// <summary>
    /// Creates a denied evaluation result.
    /// </summary>
    /// <param name="reason">The stable reason code.</param>
    /// <param name="message">An optional human-readable message.</param>
    /// <param name="scopeKey">The scope involved in the evaluation.</param>
    /// <param name="permissionKey">The permission key involved in the evaluation.</param>
    /// <param name="policyKey">The policy key involved in the evaluation.</param>
    /// <returns>A denied evaluation result.</returns>
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
