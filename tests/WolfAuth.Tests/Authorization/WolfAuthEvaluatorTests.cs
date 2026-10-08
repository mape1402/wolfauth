namespace WolfAuth.Tests.Authorization;

/// <summary>
/// Tests the core WolfAuth evaluator.
/// </summary>
public sealed class WolfAuthEvaluatorTests
{
    /// <summary>
    /// Verifies that unknown subjects are denied when known subjects are required.
    /// </summary>
    [Fact]
    public async Task CanAsync_DeniesUnknownSubject_WhenKnownSubjectsAreRequired()
    {
        var subject = TestSubject("subject-1");
        var evaluator = CreateEvaluator(options: new WolfAuthOptions { RequireKnownSubject = true });

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.view"));

        Assert.False(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.DeniedUnknownSubject, result.Reason);
    }

    /// <summary>
    /// Verifies that default access is allowed when known subjects are not required.
    /// </summary>
    [Fact]
    public async Task CanAsync_AllowsDefaultAccess_WhenKnownSubjectsAreNotRequired()
    {
        var subject = TestSubject("subject-1");
        var options = new WolfAuthOptions { RequireKnownSubject = false };
        options.DefaultAuthenticatedRoleKeys.Add("reader");
        var evaluator = CreateEvaluator(options: options);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.view"));

        Assert.True(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.AllowedByDefaultRole, result.Reason);
    }

    /// <summary>
    /// Verifies that default authenticated assignments allow access when known subjects are not required.
    /// </summary>
    [Fact]
    public async Task CanAsync_AllowsDefaultAssignment_WhenKnownSubjectsAreNotRequired()
    {
        var subject = TestSubject("subject-1");
        var options = new WolfAuthOptions { RequireKnownSubject = false };
        var store = StoreFor()
            .AddAssignment(new WolfAuthAssignment
            {
                AssignmentId = "default-reader",
                TargetKind = WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = "reader"
            })
            .Build();
        var evaluator = CreateEvaluator(store, options);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.view"));

        Assert.True(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.AllowedByDefaultRole, result.Reason);
    }

    /// <summary>
    /// Verifies that direct permission assignments allow matching actions.
    /// </summary>
    [Fact]
    public async Task CanAsync_AllowsDirectPermission()
    {
        var subject = TestSubject("subject-1");
        var store = StoreFor(subject)
            .AddAssignment(SubjectPermission("a1", subject, "contracts.events.view"))
            .Build();
        var evaluator = CreateEvaluator(store);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.view"));

        Assert.True(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.AllowedByDirectPermission, result.Reason);
    }

    /// <summary>
    /// Verifies that role assignments allow matching actions.
    /// </summary>
    [Fact]
    public async Task CanAsync_AllowsRolePermission()
    {
        var subject = TestSubject("subject-1");
        var store = StoreFor(subject)
            .AddAssignment(SubjectRole("a1", subject, "designer"))
            .Build();
        var evaluator = CreateEvaluator(store);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.version.create"));

        Assert.True(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.AllowedByRole, result.Reason);
        Assert.Equal("designer", result.RoleKey?.ToString());
    }

    /// <summary>
    /// Verifies that missing permissions produce a stable deny reason.
    /// </summary>
    [Fact]
    public async Task CanAsync_DeniesMissingPermission()
    {
        var subject = TestSubject("subject-1");
        var evaluator = CreateEvaluator(StoreFor(subject).Build());

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.delete"));

        Assert.False(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.DeniedMissingPermission, result.Reason);
    }

    /// <summary>
    /// Verifies that scoped permissions cannot be used outside their scope.
    /// </summary>
    [Fact]
    public async Task CanAsync_DeniesPermissionOutsideScope()
    {
        var subject = TestSubject("subject-1");
        var store = StoreFor(subject)
            .AddAssignment(SubjectPermission(
                "a1",
                subject,
                "distribution.releases.deploy",
                "environment:qa"))
            .Build();
        var evaluator = CreateEvaluator(store);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "distribution.releases.deploy",
            "environment:production"));

        Assert.False(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.DeniedScopeMismatch, result.Reason);
    }

    /// <summary>
    /// Verifies that external group mappings grant mapped role permissions.
    /// </summary>
    [Fact]
    public async Task CanAsync_AllowsExternalGroupMappedRole()
    {
        var subject = TestSubject("subject-1", groupIds: ["KnOwl-Reviewers"]);
        var store = StoreFor(subject)
            .AddAssignment(new WolfAuthAssignment
            {
                AssignmentId = "group-reviewer",
                TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
                ExternalGroupKey = "KnOwl-Reviewers",
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = "reviewer"
            })
            .Build();
        var evaluator = CreateEvaluator(store);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.view"));

        Assert.True(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.AllowedByExternalGroup, result.Reason);
        Assert.Equal("reviewer", result.RoleKey?.ToString());
    }

    /// <summary>
    /// Verifies that bootstrap administrators receive administrator access.
    /// </summary>
    [Fact]
    public async Task CanAsync_AllowsBootstrapAdministrator()
    {
        var subject = TestSubject("admin-1", email: "admin@example.com");
        var options = new WolfAuthOptions();
        options.BootstrapAdministrators.Add(new WolfAuthBootstrapAdministrator
        {
            Email = "ADMIN@example.com"
        });
        var evaluator = CreateEvaluator(StoreFor().Build(), options);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "security.roles.manage"));

        Assert.True(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.AllowedByBootstrapAdministrator, result.Reason);
        Assert.Equal("administrator", result.RoleKey?.ToString());
    }

    /// <summary>
    /// Verifies that unknown permissions are denied before access expansion matters.
    /// </summary>
    [Fact]
    public async Task CanAsync_DeniesUnknownPermission()
    {
        var subject = TestSubject("subject-1");
        var evaluator = CreateEvaluator(StoreFor(subject).Build());

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "unknown.permission"));

        Assert.False(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.DeniedUnknownPermission, result.Reason);
    }

    /// <summary>
    /// Verifies that unregistered policies are denied with a stable reason.
    /// </summary>
    [Fact]
    public async Task CanAsync_DeniesUnregisteredPolicy()
    {
        var subject = TestSubject("subject-1");
        var evaluator = CreateEvaluator(StoreFor(subject).Build());

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPolicy(
            subject,
            "events.promote"));

        Assert.False(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.DeniedPolicyNotRegistered, result.Reason);
    }

    /// <summary>
    /// Verifies that registered policy evaluator failures are normalized to policy failure results.
    /// </summary>
    [Fact]
    public async Task CanAsync_DeniesFailedPolicy()
    {
        var subject = TestSubject("subject-1");
        var registry = CreateRegistryBuilder()
            .AddPolicy("events.promote")
            .Build();
        var store = StoreFor(subject).Build();
        var evaluator = CreateEvaluator(
            store,
            registry: registry,
            policyEvaluators:
            [
                new TestPolicyEvaluator(
                    "events.promote",
                    WolfAuthEvaluationResult.Deny(WolfAuthEvaluationReason.DeniedMissingPermission))
            ]);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPolicy(
            subject,
            "events.promote"));

        Assert.False(result.IsAllowed);
        Assert.Equal(WolfAuthEvaluationReason.DeniedPolicyFailed, result.Reason);
    }

    /// <summary>
    /// Verifies that effective access expands direct, role, group, default, and bootstrap access.
    /// </summary>
    [Fact]
    public async Task GetEffectiveAccess_ReturnsExpandedAccess()
    {
        var subject = TestSubject("subject-1", email: "admin@example.com", groupIds: ["KnOwl-Reviewers"]);
        var options = new WolfAuthOptions { RequireKnownSubject = false };
        options.DefaultAuthenticatedRoleKeys.Add("reader");
        options.BootstrapAdministrators.Add(new WolfAuthBootstrapAdministrator
        {
            Email = "admin@example.com"
        });
        var store = StoreFor(subject)
            .AddAssignment(SubjectPermission("direct", subject, "contracts.events.delete"))
            .AddAssignment(SubjectRole("role", subject, "designer"))
            .AddAssignment(new WolfAuthAssignment
            {
                AssignmentId = "group",
                TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
                ExternalGroupKey = "KnOwl-Reviewers",
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = "reviewer"
            })
            .Build();
        var evaluator = CreateEvaluator(store, options);

        var access = await evaluator.GetEffectiveAccessAsync(subject);

        Assert.True(access.IsKnownSubject);
        Assert.Contains(access.RoleKeys, role => role.ToString() == "designer");
        Assert.Contains(access.RoleKeys, role => role.ToString() == "reviewer");
        Assert.Contains(access.RoleKeys, role => role.ToString() == "reader");
        Assert.Contains(access.RoleKeys, role => role.ToString() == "administrator");
        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.Direct);
        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.Role);
        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.ExternalGroup);
        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.Default);
        Assert.Contains(access.Permissions, grant => grant.Source == WolfAuthGrantSource.Bootstrap);
        Assert.NotEqual(default, access.EvaluatedAt);
    }

    /// <summary>
    /// Creates an evaluator wired with an in-memory store, registry, and optional policy evaluators.
    /// </summary>
    /// <param name="store">The authorization store to use.</param>
    /// <param name="options">The authorization options to use.</param>
    /// <param name="registry">The permission registry to use.</param>
    /// <param name="policyEvaluators">The policy evaluators to use.</param>
    /// <returns>A configured evaluator.</returns>
    private static WolfAuthEvaluator CreateEvaluator(
        IWolfAuthAuthorizationStore? store = null,
        WolfAuthOptions? options = null,
        IWolfAuthPermissionRegistry? registry = null,
        IEnumerable<IWolfAuthPolicyEvaluator>? policyEvaluators = null)
    {
        var effectiveOptions = options ?? new WolfAuthOptions();
        var effectiveRegistry = registry ?? CreateRegistryBuilder().Build();
        var effectiveStore = store ?? new WolfAuthInMemoryAuthorizationStoreBuilder().Build();
        var accessResolver = new WolfAuthEffectiveAccessResolver(
            effectiveStore,
            effectiveRegistry,
            effectiveOptions);

        return new WolfAuthEvaluator(
            effectiveRegistry,
            accessResolver,
            effectiveOptions,
            policyEvaluators);
    }

    /// <summary>
    /// Creates the permission registry builder used by the evaluator tests.
    /// </summary>
    /// <returns>A registry builder with common test permissions and roles.</returns>
    private static WolfAuthPermissionRegistryBuilder CreateRegistryBuilder()
    {
        return new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.events.view")
            .AddPermission("contracts.events.version.create")
            .AddPermission("contracts.events.delete")
            .AddPermission("distribution.releases.deploy")
            .AddPermission("security.roles.manage")
            .AddRole("reader", role =>
            {
                role.AddPermission("contracts.events.view");
            })
            .AddRole("designer", role =>
            {
                role.AddPermission("contracts.events.view");
                role.AddPermission("contracts.events.version.create");
            })
            .AddRole("reviewer", role =>
            {
                role.AddPermission("contracts.events.view");
            })
            .AddRole(WolfAuthRoleKey.Administrator, role =>
            {
                role.AddPermission("security.roles.manage");
            });
    }

    /// <summary>
    /// Creates an in-memory store builder with the provided known subjects.
    /// </summary>
    /// <param name="subjects">The known subjects to seed.</param>
    /// <returns>An in-memory authorization store builder.</returns>
    private static WolfAuthInMemoryAuthorizationStoreBuilder StoreFor(params WolfAuthSubject[] subjects)
    {
        var builder = new WolfAuthInMemoryAuthorizationStoreBuilder();

        foreach (var subject in subjects)
        {
            builder.AddKnownSubject(subject);
        }

        return builder;
    }

    /// <summary>
    /// Creates a normalized test subject through the development subject factory.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="email">The optional subject email.</param>
    /// <param name="groupIds">The optional external group identifiers.</param>
    /// <returns>A normalized WolfAuth subject.</returns>
    private static WolfAuthSubject TestSubject(
        string subjectId,
        string? email = null,
        IReadOnlyList<string>? groupIds = null)
    {
        return new WolfAuthDevelopmentSubjectFactory().Create(new WolfAuthDevelopmentSubjectRequest
        {
            SubjectId = subjectId,
            ExternalUserId = subjectId,
            Email = email,
            GroupIds = groupIds ?? []
        });
    }

    /// <summary>
    /// Creates a direct subject permission assignment for tests.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="subject">The target subject.</param>
    /// <param name="permissionKey">The granted permission key.</param>
    /// <param name="scopeKey">The optional grant scope.</param>
    /// <returns>A subject permission assignment.</returns>
    private static WolfAuthAssignment SubjectPermission(
        string assignmentId,
        WolfAuthSubject subject,
        WolfAuthPermissionKey permissionKey,
        WolfAuthScopeKey? scopeKey = null)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subject.SubjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = permissionKey,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global
        };
    }

    /// <summary>
    /// Creates a subject role assignment for tests.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="subject">The target subject.</param>
    /// <param name="roleKey">The granted role key.</param>
    /// <param name="scopeKey">The optional grant scope.</param>
    /// <returns>A subject role assignment.</returns>
    private static WolfAuthAssignment SubjectRole(
        string assignmentId,
        WolfAuthSubject subject,
        WolfAuthRoleKey roleKey,
        WolfAuthScopeKey? scopeKey = null)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subject.SubjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Role,
            RoleKey = roleKey,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global
        };
    }

    /// <summary>
    /// Provides a deterministic policy evaluator for tests.
    /// </summary>
    private sealed class TestPolicyEvaluator : IWolfAuthPolicyEvaluator
    {
        private readonly WolfAuthEvaluationResult _result;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestPolicyEvaluator"/> class.
        /// </summary>
        /// <param name="policyKey">The policy key handled by the evaluator.</param>
        /// <param name="result">The result returned by the evaluator.</param>
        public TestPolicyEvaluator(WolfAuthPolicyKey policyKey, WolfAuthEvaluationResult result)
        {
            PolicyKey = policyKey;
            _result = result;
        }

        /// <summary>
        /// Gets the policy key handled by the evaluator.
        /// </summary>
        public WolfAuthPolicyKey PolicyKey { get; }

        /// <summary>
        /// Returns the configured policy result.
        /// </summary>
        /// <param name="context">The policy evaluation context.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>The configured policy evaluation result.</returns>
        public ValueTask<WolfAuthEvaluationResult> EvaluateAsync(
            WolfAuthEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(_result);
        }
    }
}
