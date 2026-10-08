namespace WolfAuth;

/// <summary>
/// Identifies the kind of authorization evaluation being requested.
/// </summary>
public enum WolfAuthEvaluationKind
{
    /// <summary>
    /// The evaluation checks an atomic permission.
    /// </summary>
    Permission = 0,

    /// <summary>
    /// The evaluation checks a host-defined policy.
    /// </summary>
    Policy = 1
}

/// <summary>
/// Represents the input required to evaluate an authorization decision.
/// </summary>
public sealed record WolfAuthEvaluationContext
{
    /// <summary>
    /// Gets the subject being evaluated.
    /// </summary>
    public required WolfAuthSubject Subject { get; init; }

    /// <summary>
    /// Gets whether the evaluation targets a permission or policy.
    /// </summary>
    public required WolfAuthEvaluationKind Kind { get; init; }

    /// <summary>
    /// Gets the permission key when <see cref="Kind"/> is <see cref="WolfAuthEvaluationKind.Permission"/>.
    /// </summary>
    public WolfAuthPermissionKey? PermissionKey { get; init; }

    /// <summary>
    /// Gets the policy key when <see cref="Kind"/> is <see cref="WolfAuthEvaluationKind.Policy"/>.
    /// </summary>
    public WolfAuthPolicyKey? PolicyKey { get; init; }

    /// <summary>
    /// Gets the scope requested by the authorization check.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    /// <summary>
    /// Gets the optional resource associated with the authorization check.
    /// </summary>
    public object? Resource { get; init; }

    /// <summary>
    /// Gets host-provided evaluation data.
    /// </summary>
    public IReadOnlyDictionary<string, object?> Items { get; init; } = new Dictionary<string, object?>();

    /// <summary>
    /// Creates a permission evaluation context.
    /// </summary>
    /// <param name="subject">The subject being evaluated.</param>
    /// <param name="permissionKey">The requested permission key.</param>
    /// <param name="scopeKey">The requested scope, or global when omitted.</param>
    /// <param name="resource">The optional resource associated with the check.</param>
    /// <returns>A permission evaluation context.</returns>
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

    /// <summary>
    /// Creates a policy evaluation context.
    /// </summary>
    /// <param name="subject">The subject being evaluated.</param>
    /// <param name="policyKey">The requested policy key.</param>
    /// <param name="scopeKey">The requested scope, or global when omitted.</param>
    /// <param name="resource">The optional resource associated with the check.</param>
    /// <returns>A policy evaluation context.</returns>
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
