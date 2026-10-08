namespace WolfAuth.Tests.Core;

/// <summary>
/// Tests provisioning, administration, audit, and cache behavior.
/// </summary>
public sealed class WolfAuthProvisioningAndAdministrationTests
{
    /// <summary>
    /// Verifies that provisioning creates a subject and writes an audit record.
    /// </summary>
    [Fact]
    public async Task UpsertSubjectAsync_CreatesSubjectAndWritesAudit()
    {
        var store = new WolfAuthInMemoryPersistenceStore();
        var service = new WolfAuthProvisioningService(store, store, store);

        var result = await service.UpsertSubjectAsync(new WolfAuthProvisioningRequest
        {
            Provider = "oidc",
            ExternalUserId = "external-1",
            DisplayName = "Alex Rivera",
            Groups =
            [
                new WolfAuthExternalGroup
                {
                    Provider = "oidc",
                    ExternalGroupId = "reviewers"
                }
            ]
        });

        var storedSubject = await store.FindSubjectAsync(result.Subject.SubjectId);
        var auditRecords = await store.GetRecentAsync();

        Assert.True(result.WasCreated);
        Assert.NotNull(storedSubject);
        Assert.Contains(auditRecords, record => record.Action == WolfAuthAuditAction.SubjectProvisioned);
    }

    /// <summary>
    /// Verifies that administration validates and stores assignments.
    /// </summary>
    [Fact]
    public async Task UpsertAssignmentAsync_ValidatesStoresAndAuditsAssignment()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }]);
        var registry = TestRegistry();
        var evaluator = TestEvaluator(store, registry);
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            evaluator,
            store,
            store);

        var result = await service.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = new WolfAuthAssignment
            {
                AssignmentId = "assignment-1",
                TargetKind = WolfAuthAssignmentTargetKind.Subject,
                SubjectId = subject.SubjectId,
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = "reader"
            }
        });

        var storedAssignment = await store.FindAssignmentAsync("assignment-1");
        var auditRecords = await store.GetRecentAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(storedAssignment);
        Assert.Contains(auditRecords, record => record.Action == WolfAuthAuditAction.AssignmentUpserted);
    }

    /// <summary>
    /// Verifies that the cached resolver returns cached access until the subject is invalidated.
    /// </summary>
    [Fact]
    public async Task CachedResolver_UsesCacheUntilInvalidated()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }],
            [SubjectPermission("assignment-1", subject, "contracts.events.view")]);
        var registry = TestRegistry();
        var inner = new WolfAuthEffectiveAccessResolver(store, registry);
        var cache = new WolfAuthMemoryEffectiveAccessCache();
        var resolver = new WolfAuthCachedEffectiveAccessResolver(inner, cache);

        var firstAccess = await resolver.ResolveAsync(subject);
        await store.UpsertAssignmentAsync(SubjectPermission("assignment-2", subject, "contracts.events.delete"));
        var cachedAccess = await resolver.ResolveAsync(subject);
        cache.Invalidate(subject.SubjectId);
        var refreshedAccess = await resolver.ResolveAsync(subject);

        Assert.Contains(firstAccess.Permissions, grant => grant.PermissionKey.ToString() == "contracts.events.view");
        Assert.DoesNotContain(cachedAccess.Permissions, grant => grant.PermissionKey.ToString() == "contracts.events.delete");
        Assert.Contains(refreshedAccess.Permissions, grant => grant.PermissionKey.ToString() == "contracts.events.delete");
    }

    /// <summary>
    /// Verifies that the auditing evaluator records authorization decisions.
    /// </summary>
    [Fact]
    public async Task AuditingEvaluator_WritesDecisionAuditRecord()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }],
            [SubjectPermission("assignment-1", subject, "contracts.events.view")]);
        var registry = TestRegistry();
        var inner = TestEvaluator(store, registry);
        var evaluator = new WolfAuthAuditingEvaluator(inner, store);

        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            "contracts.events.view"));
        var auditRecords = await store.GetRecentAsync();

        Assert.True(result.IsAllowed);
        Assert.Contains(auditRecords, record => record.Action == WolfAuthAuditAction.AuthorizationEvaluated);
    }

    /// <summary>
    /// Creates a test evaluator.
    /// </summary>
    /// <param name="store">The authorization store.</param>
    /// <param name="registry">The permission registry.</param>
    /// <returns>The configured evaluator.</returns>
    private static IWolfAuthEvaluator TestEvaluator(
        IWolfAuthAuthorizationStore store,
        IWolfAuthPermissionRegistry registry)
    {
        return new WolfAuthEvaluator(
            registry,
            new WolfAuthEffectiveAccessResolver(store, registry));
    }

    /// <summary>
    /// Creates a registry for tests.
    /// </summary>
    /// <returns>The configured registry.</returns>
    private static IWolfAuthPermissionRegistry TestRegistry()
    {
        return new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.events.view")
            .AddPermission("contracts.events.delete")
            .AddRole("reader", role => role.AddPermission("contracts.events.view"))
            .Build();
    }

    /// <summary>
    /// Creates a test subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The test subject.</returns>
    private static WolfAuthSubject TestSubject(string subjectId)
    {
        return new WolfAuthSubject
        {
            SubjectId = subjectId,
            Provider = "test",
            ExternalUserId = subjectId
        };
    }

    /// <summary>
    /// Creates a subject permission assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="subject">The target subject.</param>
    /// <param name="permissionKey">The permission key.</param>
    /// <returns>The assignment.</returns>
    private static WolfAuthAssignment SubjectPermission(
        string assignmentId,
        WolfAuthSubject subject,
        WolfAuthPermissionKey permissionKey)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subject.SubjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = permissionKey
        };
    }
}
