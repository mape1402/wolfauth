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
    /// Verifies that provisioning updates an existing subject resolved by external identity.
    /// </summary>
    [Fact]
    public async Task UpsertSubjectAsync_UpdatesExistingSubjectByExternalIdentity()
    {
        var store = new WolfAuthInMemoryPersistenceStore();
        var service = new WolfAuthProvisioningService(store, store, store);

        var created = await service.UpsertSubjectAsync(new WolfAuthProvisioningRequest
        {
            Provider = "oidc",
            ExternalUserId = "external-1",
            DisplayName = "Old Name"
        });
        var updated = await service.UpsertSubjectAsync(new WolfAuthProvisioningRequest
        {
            Provider = "oidc",
            ExternalUserId = "external-1",
            DisplayName = "New Name",
            IsActive = false
        });

        var storedSubject = await store.FindSubjectAsync(created.Subject.SubjectId);

        Assert.False(updated.WasCreated);
        Assert.Equal(created.Subject.SubjectId, updated.Subject.SubjectId);
        Assert.NotNull(storedSubject);
        Assert.Equal("New Name", storedSubject.Subject.DisplayName);
        Assert.False(storedSubject.IsActive);
    }

    /// <summary>
    /// Verifies that provisioning can deactivate an existing subject.
    /// </summary>
    [Fact]
    public async Task DeactivateSubjectAsync_DeactivatesExistingSubjectAndAudits()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }]);
        var service = new WolfAuthProvisioningService(store, store, store);

        var deactivated = await service.DeactivateSubjectAsync(subject.SubjectId);
        var storedSubject = await store.FindSubjectAsync(subject.SubjectId);
        var missing = await service.DeactivateSubjectAsync("missing");
        var auditRecords = await store.GetRecentAsync();

        Assert.True(deactivated);
        Assert.False(missing);
        Assert.NotNull(storedSubject);
        Assert.False(storedSubject.IsActive);
        Assert.Contains(auditRecords, record => record.Action == WolfAuthAuditAction.SubjectDeactivated);
    }

    /// <summary>
    /// Verifies that provisioning works without optional unit of work and audit dependencies.
    /// </summary>
    [Fact]
    public async Task UpsertSubjectAsync_WorksWithoutOptionalDependencies()
    {
        var store = new WolfAuthInMemoryPersistenceStore();
        var service = new WolfAuthProvisioningService(store);

        var result = await service.UpsertSubjectAsync(new WolfAuthProvisioningRequest
        {
            SubjectId = "subject-1",
            Provider = "oidc",
            ExternalUserId = "external-1"
        });

        Assert.True(result.WasCreated);
        Assert.Equal("subject-1", result.Subject.SubjectId.ToString());
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
    /// Verifies that administration stores valid assignments without optional collaborators.
    /// </summary>
    [Fact]
    public async Task UpsertAssignmentAsync_WorksWithoutOptionalUnitOfWorkAuditAndCache()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }]);
        var registry = TestRegistry();
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            TestEvaluator(store, registry));

        var result = await service.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = SubjectPermission("assignment-1", subject, "contracts.events.view")
        });

        var storedAssignment = await store.FindAssignmentAsync("assignment-1");
        var auditRecords = await store.GetRecentAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(storedAssignment);
        Assert.Empty(auditRecords);
    }

    /// <summary>
    /// Verifies that administration returns validation errors without storing invalid assignments.
    /// </summary>
    [Fact]
    public async Task UpsertAssignmentAsync_ReturnsValidationErrors_ForInvalidAssignment()
    {
        var store = new WolfAuthInMemoryPersistenceStore();
        var registry = TestRegistry();
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            TestEvaluator(store, registry));

        var result = await service.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = new WolfAuthAssignment
            {
                AssignmentId = "invalid",
                TargetKind = WolfAuthAssignmentTargetKind.Subject,
                GrantKind = WolfAuthAssignmentGrantKind.Permission,
                PermissionKey = "unknown.permission"
            }
        });
        var storedAssignment = await store.FindAssignmentAsync("invalid");

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Validation);
        Assert.False(result.Validation.IsValid);
        Assert.Null(storedAssignment);
    }

    /// <summary>
    /// Verifies assignment removal success, not found, auditing, and cache invalidation.
    /// </summary>
    [Fact]
    public async Task RemoveAssignmentAsync_RemovesExistingAssignmentsAndInvalidatesCache()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }],
            [SubjectPermission("assignment-1", subject, "contracts.events.view")]);
        var registry = TestRegistry();
        var cache = new WolfAuthMemoryEffectiveAccessCache();
        cache.Set(new WolfAuthEffectiveAccess { Subject = subject });
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            TestEvaluator(store, registry),
            store,
            store,
            cache);

        var removed = await service.RemoveAssignmentAsync("assignment-1", "actor-1");
        var removedAgain = await service.RemoveAssignmentAsync("assignment-1");
        var storedAssignment = await store.FindAssignmentAsync("assignment-1");
        var auditRecords = await store.GetRecentAsync();

        Assert.True(removed);
        Assert.False(removedAgain);
        Assert.Null(storedAssignment);
        Assert.False(cache.TryGet(subject.SubjectId, out _));
        Assert.Contains(auditRecords, record => record.Action == WolfAuthAuditAction.AssignmentRemoved);
    }

    /// <summary>
    /// Verifies that removing group assignments invalidates the full cache.
    /// </summary>
    [Fact]
    public async Task RemoveAssignmentAsync_InvalidatesAllCache_ForGroupAssignment()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }],
            [
                new WolfAuthAssignment
                {
                    AssignmentId = "group-assignment",
                    TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
                    ExternalGroupKey = "reviewers",
                    GrantKind = WolfAuthAssignmentGrantKind.Role,
                    RoleKey = "reader"
                }
            ]);
        var registry = TestRegistry();
        var cache = new WolfAuthMemoryEffectiveAccessCache();
        cache.Set(new WolfAuthEffectiveAccess { Subject = subject });
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            TestEvaluator(store, registry),
            cache: cache);

        var removed = await service.RemoveAssignmentAsync("group-assignment");

        Assert.True(removed);
        Assert.False(cache.TryGet(subject.SubjectId, out _));
    }

    /// <summary>
    /// Verifies that group assignments invalidate the full cache because affected subjects are broad.
    /// </summary>
    [Fact]
    public async Task UpsertAssignmentAsync_InvalidatesAllCache_ForGroupAssignment()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore([new WolfAuthStoredSubject { Subject = subject }]);
        var registry = TestRegistry();
        var cache = new WolfAuthMemoryEffectiveAccessCache();
        cache.Set(new WolfAuthEffectiveAccess { Subject = subject });
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            TestEvaluator(store, registry),
            cache: cache);

        var result = await service.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = new WolfAuthAssignment
            {
                AssignmentId = "group-assignment",
                TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
                ExternalGroupKey = "reviewers",
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = "reader"
            }
        });

        Assert.True(result.Succeeded);
        Assert.False(cache.TryGet(subject.SubjectId, out _));
    }

    /// <summary>
    /// Verifies that broad assignments work when no cache is configured.
    /// </summary>
    [Fact]
    public async Task UpsertAssignmentAsync_StoresBroadAssignment_WhenCacheIsNotConfigured()
    {
        var store = new WolfAuthInMemoryPersistenceStore();
        var registry = TestRegistry();
        var service = new WolfAuthAdministrationService(
            store,
            new WolfAuthAssignmentValidator(registry),
            TestEvaluator(store, registry));

        var result = await service.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            Assignment = new WolfAuthAssignment
            {
                AssignmentId = "group-assignment",
                TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
                ExternalGroupKey = "reviewers",
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = "reader"
            }
        });

        var storedAssignment = await store.FindAssignmentAsync("group-assignment");

        Assert.True(result.Succeeded);
        Assert.NotNull(storedAssignment);
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
    /// Verifies cache expiration and global invalidation behavior.
    /// </summary>
    [Fact]
    public void MemoryCache_ExpiresEntriesAndInvalidatesAll()
    {
        var subject = TestSubject("subject-1");
        var cache = new WolfAuthMemoryEffectiveAccessCache(
            new WolfAuthEffectiveAccessCacheOptions { TimeToLive = TimeSpan.FromMilliseconds(-1) });
        cache.Set(new WolfAuthEffectiveAccess { Subject = subject });

        var expired = cache.TryGet(subject.SubjectId, out _);

        cache = new WolfAuthMemoryEffectiveAccessCache();
        cache.Set(new WolfAuthEffectiveAccess { Subject = subject });
        cache.InvalidateAll();
        var invalidated = cache.TryGet(subject.SubjectId, out _);

        Assert.False(expired);
        Assert.False(invalidated);
        Assert.Throws<ArgumentNullException>(() => cache.Set(null!));
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
    /// Verifies that auditing evaluator forwards effective access and records policy metadata.
    /// </summary>
    [Fact]
    public async Task AuditingEvaluator_ForwardsEffectiveAccessAndAuditsPolicyMetadata()
    {
        var subject = TestSubject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore();
        var inner = new FixedEvaluator(new WolfAuthEffectiveAccess { Subject = subject });
        var evaluator = new WolfAuthAuditingEvaluator(inner, store);

        var access = await evaluator.GetEffectiveAccessAsync(subject);
        var result = await evaluator.CanAsync(WolfAuthEvaluationContext.ForPolicy(
            subject,
            "events.promote"));
        var auditRecords = await store.GetRecentAsync();

        Assert.Same(subject, access.Subject);
        Assert.True(result.IsAllowed);
        Assert.Contains(auditRecords, record =>
            record.Metadata.TryGetValue("policy", out var policy) &&
            policy == "events.promote");
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

    /// <summary>
    /// Provides fixed evaluator behavior for auditing tests.
    /// </summary>
    private sealed class FixedEvaluator : IWolfAuthEvaluator
    {
        private readonly WolfAuthEffectiveAccess _effectiveAccess;

        /// <summary>
        /// Initializes a new instance of the <see cref="FixedEvaluator"/> class.
        /// </summary>
        /// <param name="effectiveAccess">The effective access returned by the evaluator.</param>
        public FixedEvaluator(WolfAuthEffectiveAccess effectiveAccess)
        {
            _effectiveAccess = effectiveAccess;
        }

        /// <inheritdoc />
        public ValueTask<WolfAuthEvaluationResult> CanAsync(
            WolfAuthEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(WolfAuthEvaluationResult.Allow(WolfAuthEvaluationReason.Allowed));
        }

        /// <inheritdoc />
        public ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
            WolfAuthSubject subject,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(_effectiveAccess);
        }
    }
}
