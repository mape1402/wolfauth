namespace WolfAuth.Tests.Authorization;

/// <summary>
/// Tests effective access expansion edge cases.
/// </summary>
public sealed class WolfAuthEffectiveAccessResolverTests
{
    /// <summary>
    /// Verifies that default authenticated assignments are skipped when known subjects are required.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_SkipsDefaultAssignments_WhenKnownSubjectsAreRequired()
    {
        var subject = Subject("subject-1");
        var store = new WolfAuthInMemoryAuthorizationStore(
            assignments:
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "default-permission",
                    TargetKind = WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
                    GrantKind = WolfAuthAssignmentGrantKind.Permission,
                    PermissionKey = "contracts.view"
                }
            ]);
        var resolver = new WolfAuthEffectiveAccessResolver(store, Registry());

        var access = await resolver.ResolveAsync(subject);

        Assert.Empty(access.Permissions);
    }

    /// <summary>
    /// Verifies direct permission grants from external group assignments.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ExpandsExternalGroupPermissionAssignments()
    {
        var subject = Subject("subject-1", groupIds: ["reviewers"]);
        var store = new WolfAuthInMemoryAuthorizationStore(
            knownSubjectIds: [subject.SubjectId],
            assignments:
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "group-permission",
                    TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
                    ExternalGroupKey = "reviewers",
                    GrantKind = WolfAuthAssignmentGrantKind.Permission,
                    PermissionKey = "contracts.view"
                }
            ]);
        var resolver = new WolfAuthEffectiveAccessResolver(store, Registry());

        var access = await resolver.ResolveAsync(subject);

        Assert.Contains(access.Permissions, grant =>
            grant.PermissionKey.ToString() == "contracts.view" &&
            grant.Source == WolfAuthGrantSource.ExternalGroup);
    }

    /// <summary>
    /// Verifies that unknown roles are recorded but do not expand permissions.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_RecordsUnknownRoleWithoutPermissions()
    {
        var subject = Subject("subject-1");
        var store = new WolfAuthInMemoryAuthorizationStore(
            knownSubjectIds: [subject.SubjectId],
            assignments:
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "unknown-role",
                    TargetKind = WolfAuthAssignmentTargetKind.Subject,
                    SubjectId = subject.SubjectId,
                    GrantKind = WolfAuthAssignmentGrantKind.Role,
                    RoleKey = "unknown"
                }
            ]);
        var resolver = new WolfAuthEffectiveAccessResolver(store, Registry());

        var access = await resolver.ResolveAsync(subject);

        Assert.Contains(access.RoleKeys, role => role.ToString() == "unknown");
        Assert.Empty(access.Permissions);
    }

    /// <summary>
    /// Verifies bootstrap matching by subject id and provider external id.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ExpandsBootstrapAdministrators_BySubjectAndExternalIdentity()
    {
        var subject = Subject("subject-1");
        var options = new WolfAuthOptions();
        options.BootstrapAdministrators.Add(new WolfAuthBootstrapAdministrator
        {
            SubjectId = "subject-1"
        });
        options.BootstrapAdministrators.Add(new WolfAuthBootstrapAdministrator
        {
            Provider = "test",
            ExternalUserId = "subject-1"
        });
        var resolver = new WolfAuthEffectiveAccessResolver(
            new WolfAuthInMemoryAuthorizationStore(),
            Registry(),
            options);

        var access = await resolver.ResolveAsync(subject);

        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.Bootstrap);
    }

    /// <summary>
    /// Verifies that role permissions with explicit scopes keep those scopes.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_KeepsExplicitRolePermissionScope()
    {
        var subject = Subject("subject-1");
        var registry = new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.view")
            .AddRole("scoped-reader", role => role.AddPermission("contracts.view", "environment:prod"))
            .Build();
        var store = new WolfAuthInMemoryAuthorizationStore(
            knownSubjectIds: [subject.SubjectId],
            assignments:
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "scoped-role",
                    TargetKind = WolfAuthAssignmentTargetKind.Subject,
                    SubjectId = subject.SubjectId,
                    GrantKind = WolfAuthAssignmentGrantKind.Role,
                    RoleKey = "scoped-reader",
                    ScopeKey = "environment:qa"
                }
            ]);
        var resolver = new WolfAuthEffectiveAccessResolver(store, registry);

        var access = await resolver.ResolveAsync(subject);

        Assert.Contains(access.Permissions, grant => grant.ScopeKey.ToString() == "environment:prod");
    }

    /// <summary>
    /// Verifies malformed grants are ignored without preventing other valid grants from expanding.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_IgnoresMalformedAssignments()
    {
        var subject = Subject("subject-1");
        var store = new WolfAuthInMemoryAuthorizationStore(
            knownSubjectIds: [subject.SubjectId],
            assignments:
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "missing-permission-key",
                    TargetKind = WolfAuthAssignmentTargetKind.Subject,
                    SubjectId = subject.SubjectId,
                    GrantKind = WolfAuthAssignmentGrantKind.Permission
                },
                new WolfAuthAssignment
                {
                    AssignmentId = "missing-role-key",
                    TargetKind = WolfAuthAssignmentTargetKind.Subject,
                    SubjectId = subject.SubjectId,
                    GrantKind = WolfAuthAssignmentGrantKind.Role
                }
            ]);
        var resolver = new WolfAuthEffectiveAccessResolver(store, Registry());

        var access = await resolver.ResolveAsync(subject);

        Assert.Empty(access.Permissions);
        Assert.Empty(access.RoleKeys);
    }

    /// <summary>
    /// Verifies bootstrap assignment sources can be expanded when supplied by a store.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ExpandsBootstrapAssignments_FromStore()
    {
        var subject = Subject("subject-1");
        var resolver = new WolfAuthEffectiveAccessResolver(
            new StaticAuthorizationStore(
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "bootstrap-role",
                    TargetKind = WolfAuthAssignmentTargetKind.BootstrapAdministrator,
                    GrantKind = WolfAuthAssignmentGrantKind.Role,
                    RoleKey = WolfAuthRoleKey.Administrator
                }
            ]),
            Registry());

        var access = await resolver.ResolveAsync(subject);

        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.Bootstrap);
    }

    /// <summary>
    /// Verifies bootstrap matching rejects incomplete provider and email rules.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_SkipsIncompleteBootstrapAdministratorRules()
    {
        var subject = Subject("subject-1");
        var options = new WolfAuthOptions();
        options.BootstrapAdministrators.Add(new WolfAuthBootstrapAdministrator
        {
            Provider = "test"
        });
        options.BootstrapAdministrators.Add(new WolfAuthBootstrapAdministrator
        {
            Email = "   "
        });
        var resolver = new WolfAuthEffectiveAccessResolver(
            new WolfAuthInMemoryAuthorizationStore(),
            Registry(),
            options);

        var access = await resolver.ResolveAsync(subject);

        Assert.Empty(access.Permissions);
        Assert.Empty(access.RoleKeys);
    }

    /// <summary>
    /// Verifies resolver guards null subjects.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ThrowsForNullSubject()
    {
        var resolver = new WolfAuthEffectiveAccessResolver(
            new WolfAuthInMemoryAuthorizationStore(),
            Registry());

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await resolver.ResolveAsync(null!));
    }

    /// <summary>
    /// Creates a test registry.
    /// </summary>
    /// <returns>The registry.</returns>
    private static IWolfAuthPermissionRegistry Registry()
    {
        return new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.view")
            .AddPermission("security.roles.manage")
            .AddRole(WolfAuthRoleKey.Administrator, role => role.AddPermission("security.roles.manage"))
            .Build();
    }

    /// <summary>
    /// Creates a test subject.
    /// </summary>
    /// <param name="subjectId">The subject id.</param>
    /// <param name="groupIds">The group ids.</param>
    /// <returns>The subject.</returns>
    private static WolfAuthSubject Subject(string subjectId, IReadOnlyList<string>? groupIds = null)
    {
        return new WolfAuthSubject
        {
            SubjectId = subjectId,
            Provider = "test",
            ExternalUserId = subjectId,
            Groups = (groupIds ?? [])
                .Select(groupId => new WolfAuthExternalGroup
                {
                    Provider = "test",
                    ExternalGroupId = groupId
                })
                .ToArray()
        };
    }

    /// <summary>
    /// Provides fixed assignments to resolver tests without applying target filtering.
    /// </summary>
    private sealed class StaticAuthorizationStore : IWolfAuthAuthorizationStore
    {
        private readonly IReadOnlyList<WolfAuthAssignment> _assignments;

        /// <summary>
        /// Initializes a new instance of the <see cref="StaticAuthorizationStore"/> class.
        /// </summary>
        /// <param name="assignments">The assignments returned by the store.</param>
        public StaticAuthorizationStore(IReadOnlyList<WolfAuthAssignment> assignments)
        {
            _assignments = assignments;
        }

        /// <inheritdoc />
        public ValueTask<bool> IsKnownSubjectAsync(
            WolfAuthSubject subject,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(true);
        }

        /// <inheritdoc />
        public ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
            WolfAuthSubject subject,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(_assignments);
        }
    }
}
