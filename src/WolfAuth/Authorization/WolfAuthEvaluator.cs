namespace WolfAuth;

/// <summary>
/// Evaluates WolfAuth authorization decisions using effective access and host policy evaluators.
/// </summary>
public sealed class WolfAuthEvaluator : IWolfAuthEvaluator
{
    private readonly IWolfAuthPermissionRegistry _registry;
    private readonly IWolfAuthEffectiveAccessResolver _effectiveAccessResolver;
    private readonly WolfAuthOptions _options;
    private readonly IReadOnlyDictionary<WolfAuthPolicyKey, IWolfAuthPolicyEvaluator> _policyEvaluators;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthEvaluator"/> class.
    /// </summary>
    /// <param name="registry">The host permission registry.</param>
    /// <param name="effectiveAccessResolver">The effective access resolver.</param>
    /// <param name="options">The authorization options.</param>
    /// <param name="policyEvaluators">Host policy evaluators.</param>
    public WolfAuthEvaluator(
        IWolfAuthPermissionRegistry registry,
        IWolfAuthEffectiveAccessResolver effectiveAccessResolver,
        WolfAuthOptions? options = null,
        IEnumerable<IWolfAuthPolicyEvaluator>? policyEvaluators = null)
    {
        _registry = registry;
        _effectiveAccessResolver = effectiveAccessResolver;
        _options = options ?? new WolfAuthOptions();
        _policyEvaluators = (policyEvaluators ?? [])
            .GroupBy(evaluator => evaluator.PolicyKey)
            .ToDictionary(group => group.Key, group => group.First());
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthEvaluationResult> CanAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return context.Kind switch
        {
            WolfAuthEvaluationKind.Permission => await EvaluatePermissionAsync(context, cancellationToken),
            WolfAuthEvaluationKind.Policy => await EvaluatePolicyAsync(context, cancellationToken),
            _ => WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedInvalidRequest,
                "The evaluation kind is not supported.",
                context.ScopeKey)
        };
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        return _effectiveAccessResolver.ResolveAsync(subject, cancellationToken);
    }

    /// <summary>
    /// Evaluates a permission request against expanded effective access.
    /// </summary>
    /// <param name="context">The evaluation context.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The permission evaluation result.</returns>
    private async ValueTask<WolfAuthEvaluationResult> EvaluatePermissionAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken)
    {
        if (context.PermissionKey is not { } permissionKey)
        {
            return WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedInvalidRequest,
                "A permission evaluation requires a permission key.",
                context.ScopeKey);
        }

        if (!_registry.TryGetPermission(permissionKey, out _))
        {
            return WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedUnknownPermission,
                "The requested permission is not registered.",
                context.ScopeKey,
                permissionKey);
        }

        var effectiveAccess = await _effectiveAccessResolver.ResolveAsync(context.Subject, cancellationToken);

        if (_options.RequireKnownSubject && !effectiveAccess.IsKnownSubject && !HasBootstrapGrant(effectiveAccess))
        {
            return WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedUnknownSubject,
                "The subject is not known by the authorization store.",
                context.ScopeKey,
                permissionKey) with
            {
                EffectiveAccess = effectiveAccess
            };
        }

        var matchingGrant = FindMatchingGrant(effectiveAccess, permissionKey, context.ScopeKey);
        if (matchingGrant is not null)
        {
            return WolfAuthEvaluationResult.Allow(
                GetAllowedReason(matchingGrant.Source),
                context.ScopeKey,
                permissionKey,
                roleKey: matchingGrant.RoleKey,
                effectiveAccess: effectiveAccess);
        }

        var hasSamePermissionElsewhere = effectiveAccess.Permissions.Any(grant =>
            grant.PermissionKey == permissionKey &&
            grant.ScopeKey != WolfAuthScopeKey.Global &&
            grant.ScopeKey != context.ScopeKey);

        return WolfAuthEvaluationResult.Deny(
            hasSamePermissionElsewhere
                ? WolfAuthEvaluationReason.DeniedScopeMismatch
                : WolfAuthEvaluationReason.DeniedMissingPermission,
            hasSamePermissionElsewhere
                ? "The subject has the requested permission, but not for the requested scope."
                : "The subject does not have the requested permission.",
            context.ScopeKey,
            permissionKey) with
        {
            EffectiveAccess = effectiveAccess
        };
    }

    /// <summary>
    /// Evaluates a policy request by checking required permissions and dispatching to a host evaluator.
    /// </summary>
    /// <param name="context">The evaluation context.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The policy evaluation result.</returns>
    private async ValueTask<WolfAuthEvaluationResult> EvaluatePolicyAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken)
    {
        if (context.PolicyKey is not { } policyKey)
        {
            return WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedInvalidRequest,
                "A policy evaluation requires a policy key.",
                context.ScopeKey);
        }

        if (!_registry.TryGetPolicy(policyKey, out var policy) || policy is null)
        {
            return WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedPolicyNotRegistered,
                "The requested policy is not registered.",
                context.ScopeKey,
                policyKey: policyKey);
        }

        foreach (var requiredPermission in policy.RequiredPermissions)
        {
            var requiredPermissionResult = await EvaluatePermissionAsync(
                WolfAuthEvaluationContext.ForPermission(
                    context.Subject,
                    requiredPermission,
                    context.ScopeKey,
                    context.Resource),
                cancellationToken);

            if (!requiredPermissionResult.IsAllowed)
            {
                return WolfAuthEvaluationResult.Deny(
                    WolfAuthEvaluationReason.DeniedPolicyFailed,
                    "A required permission for the policy was not satisfied.",
                    context.ScopeKey,
                    policyKey: policyKey) with
                {
                    EffectiveAccess = requiredPermissionResult.EffectiveAccess,
                    Diagnostics = [$"Required permission failed: {requiredPermission}."]
                };
            }
        }

        if (!_policyEvaluators.TryGetValue(policyKey, out var policyEvaluator))
        {
            return WolfAuthEvaluationResult.Deny(
                WolfAuthEvaluationReason.DeniedPolicyNotRegistered,
                "No policy evaluator is registered for the requested policy.",
                context.ScopeKey,
                policyKey: policyKey);
        }

        var result = await policyEvaluator.EvaluateAsync(context, cancellationToken);
        if (result.IsAllowed)
        {
            return result;
        }

        return result.Reason == WolfAuthEvaluationReason.DeniedPolicyFailed
            ? result
            : result with { Reason = WolfAuthEvaluationReason.DeniedPolicyFailed };
    }

    /// <summary>
    /// Finds a grant that satisfies the requested permission and scope.
    /// </summary>
    /// <param name="effectiveAccess">The effective access snapshot.</param>
    /// <param name="permissionKey">The requested permission key.</param>
    /// <param name="scopeKey">The requested scope key.</param>
    /// <returns>The matching grant when one exists; otherwise, <c>null</c>.</returns>
    private static WolfAuthPermissionGrant? FindMatchingGrant(
        WolfAuthEffectiveAccess effectiveAccess,
        WolfAuthPermissionKey permissionKey,
        WolfAuthScopeKey scopeKey)
    {
        return effectiveAccess.Permissions.FirstOrDefault(grant =>
            grant.PermissionKey == permissionKey &&
            (grant.ScopeKey == WolfAuthScopeKey.Global || grant.ScopeKey == scopeKey));
    }

    /// <summary>
    /// Determines whether effective access contains a bootstrap administrator grant.
    /// </summary>
    /// <param name="effectiveAccess">The effective access snapshot.</param>
    /// <returns><c>true</c> when bootstrap access exists; otherwise, <c>false</c>.</returns>
    private static bool HasBootstrapGrant(WolfAuthEffectiveAccess effectiveAccess)
    {
        return effectiveAccess.Permissions.Any(grant => grant.Source == WolfAuthGrantSource.Bootstrap);
    }

    /// <summary>
    /// Maps a grant source to the corresponding allow reason.
    /// </summary>
    /// <param name="grantSource">The source that produced the matching grant.</param>
    /// <returns>The allow reason for the grant source.</returns>
    private static WolfAuthEvaluationReason GetAllowedReason(WolfAuthGrantSource grantSource)
    {
        return grantSource switch
        {
            WolfAuthGrantSource.Direct => WolfAuthEvaluationReason.AllowedByDirectPermission,
            WolfAuthGrantSource.Role => WolfAuthEvaluationReason.AllowedByRole,
            WolfAuthGrantSource.ExternalGroup => WolfAuthEvaluationReason.AllowedByExternalGroup,
            WolfAuthGrantSource.Bootstrap => WolfAuthEvaluationReason.AllowedByBootstrapAdministrator,
            WolfAuthGrantSource.Default => WolfAuthEvaluationReason.AllowedByDefaultRole,
            _ => WolfAuthEvaluationReason.Allowed
        };
    }
}
