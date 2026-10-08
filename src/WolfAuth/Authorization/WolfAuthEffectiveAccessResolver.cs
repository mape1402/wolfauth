namespace WolfAuth;

/// <summary>
/// Expands effective access from assignments, roles, external groups, defaults, and bootstrap administrator rules.
/// </summary>
public sealed class WolfAuthEffectiveAccessResolver : IWolfAuthEffectiveAccessResolver
{
    private readonly IWolfAuthAuthorizationStore _store;
    private readonly IWolfAuthPermissionRegistry _registry;
    private readonly WolfAuthOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthEffectiveAccessResolver"/> class.
    /// </summary>
    /// <param name="store">The authorization store.</param>
    /// <param name="registry">The permission registry.</param>
    /// <param name="options">The authorization options.</param>
    public WolfAuthEffectiveAccessResolver(
        IWolfAuthAuthorizationStore store,
        IWolfAuthPermissionRegistry registry,
        WolfAuthOptions? options = null)
    {
        _store = store;
        _registry = registry;
        _options = options ?? new WolfAuthOptions();
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthEffectiveAccess> ResolveAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        var isKnownSubject = await _store.IsKnownSubjectAsync(subject, cancellationToken);
        var assignments = await _store.GetAssignmentsAsync(subject, cancellationToken);
        var grants = new List<WolfAuthPermissionGrant>();
        var roleKeys = new List<WolfAuthRoleKey>();

        foreach (var assignment in assignments)
        {
            if (assignment.TargetKind == WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject &&
                _options.RequireKnownSubject)
            {
                continue;
            }

            ExpandAssignment(assignment, grants, roleKeys);
        }

        if (!_options.RequireKnownSubject)
        {
            foreach (var defaultRoleKey in _options.DefaultAuthenticatedRoleKeys)
            {
                ExpandRole(
                    defaultRoleKey,
                    WolfAuthScopeKey.Global,
                    WolfAuthGrantSource.Default,
                    grants,
                    roleKeys);
            }
        }

        foreach (var bootstrapAdministrator in _options.BootstrapAdministrators)
        {
            if (!MatchesBootstrapAdministrator(subject, bootstrapAdministrator))
            {
                continue;
            }

            ExpandRole(
                bootstrapAdministrator.RoleKey,
                WolfAuthScopeKey.Global,
                WolfAuthGrantSource.Bootstrap,
                grants,
                roleKeys);
        }

        return new WolfAuthEffectiveAccess
        {
            Subject = subject,
            IsKnownSubject = isKnownSubject,
            RoleKeys = roleKeys.Distinct().ToArray(),
            Permissions = grants.Distinct().ToArray(),
            ExternalGroups = subject.Groups,
            EvaluatedAt = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Expands an assignment into direct permission grants or role grants.
    /// </summary>
    /// <param name="assignment">The assignment to expand.</param>
    /// <param name="grants">The mutable grant collection.</param>
    /// <param name="roleKeys">The mutable role collection.</param>
    private void ExpandAssignment(
        WolfAuthAssignment assignment,
        List<WolfAuthPermissionGrant> grants,
        List<WolfAuthRoleKey> roleKeys)
    {
        var source = GetGrantSource(assignment);

        if (assignment.GrantKind == WolfAuthAssignmentGrantKind.Permission &&
            assignment.PermissionKey is { } permissionKey)
        {
            grants.Add(new WolfAuthPermissionGrant
            {
                PermissionKey = permissionKey,
                ScopeKey = assignment.ScopeKey,
                Source = source,
                ExternalGroupKey = assignment.ExternalGroupKey
            });

            return;
        }

        if (assignment.GrantKind == WolfAuthAssignmentGrantKind.Role &&
            assignment.RoleKey is { } roleKey)
        {
            ExpandRole(
                roleKey,
                assignment.ScopeKey,
                source,
                grants,
                roleKeys,
                assignment.ExternalGroupKey);
        }
    }

    /// <summary>
    /// Expands a role into its permissions for the assignment scope.
    /// </summary>
    /// <param name="roleKey">The role key to expand.</param>
    /// <param name="assignmentScopeKey">The scope inherited from the assignment.</param>
    /// <param name="source">The source that produced the role grant.</param>
    /// <param name="grants">The mutable grant collection.</param>
    /// <param name="roleKeys">The mutable role collection.</param>
    /// <param name="externalGroupKey">The external group that produced the grant when applicable.</param>
    private void ExpandRole(
        WolfAuthRoleKey roleKey,
        WolfAuthScopeKey assignmentScopeKey,
        WolfAuthGrantSource source,
        List<WolfAuthPermissionGrant> grants,
        List<WolfAuthRoleKey> roleKeys,
        WolfAuthExternalGroupKey? externalGroupKey = null)
    {
        roleKeys.Add(roleKey);

        if (!_registry.TryGetRole(roleKey, out var role) || role is null)
        {
            return;
        }

        foreach (var permission in role.Permissions)
        {
            grants.Add(new WolfAuthPermissionGrant
            {
                PermissionKey = permission.PermissionKey,
                ScopeKey = permission.ScopeKey == WolfAuthScopeKey.Global
                    ? assignmentScopeKey
                    : permission.ScopeKey,
                Source = source,
                RoleKey = roleKey,
                ExternalGroupKey = externalGroupKey
            });
        }
    }

    /// <summary>
    /// Gets the grant source represented by an assignment.
    /// </summary>
    /// <param name="assignment">The assignment to inspect.</param>
    /// <returns>The source represented by the assignment.</returns>
    private static WolfAuthGrantSource GetGrantSource(WolfAuthAssignment assignment)
    {
        return assignment.TargetKind switch
        {
            WolfAuthAssignmentTargetKind.ExternalGroup => WolfAuthGrantSource.ExternalGroup,
            WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject => WolfAuthGrantSource.Default,
            WolfAuthAssignmentTargetKind.BootstrapAdministrator => WolfAuthGrantSource.Bootstrap,
            _ => assignment.GrantKind == WolfAuthAssignmentGrantKind.Role
                ? WolfAuthGrantSource.Role
                : WolfAuthGrantSource.Direct
        };
    }

    /// <summary>
    /// Determines whether a subject matches a bootstrap administrator rule.
    /// </summary>
    /// <param name="subject">The subject to compare.</param>
    /// <param name="bootstrapAdministrator">The bootstrap administrator rule.</param>
    /// <returns><c>true</c> when the subject matches the rule; otherwise, <c>false</c>.</returns>
    private static bool MatchesBootstrapAdministrator(
        WolfAuthSubject subject,
        WolfAuthBootstrapAdministrator bootstrapAdministrator)
    {
        if (bootstrapAdministrator.SubjectId is { } subjectId &&
            subject.SubjectId == subjectId)
        {
            return true;
        }

        if (bootstrapAdministrator.Provider is { } provider &&
            bootstrapAdministrator.ExternalUserId is { } externalUserId &&
            subject.Provider == provider &&
            subject.ExternalUserId == externalUserId)
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(bootstrapAdministrator.Email) &&
            !string.IsNullOrWhiteSpace(subject.Email) &&
            string.Equals(
                bootstrapAdministrator.Email.Trim(),
                subject.Email.Trim(),
                StringComparison.OrdinalIgnoreCase);
    }
}
