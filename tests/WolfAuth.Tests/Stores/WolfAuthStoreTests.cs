namespace WolfAuth.Tests.Stores;

/// <summary>
/// Tests in-memory WolfAuth stores.
/// </summary>
public sealed class WolfAuthStoreTests
{
    /// <summary>
    /// Verifies in-memory authorization store assignment matching.
    /// </summary>
    [Fact]
    public async Task AuthorizationStore_ReturnsMatchingAssignmentsOnly()
    {
        var subject = Subject("subject-1", groupIds: ["reviewers"]);
        var store = new WolfAuthInMemoryAuthorizationStore(
            knownSubjectIds: [subject.SubjectId],
            assignments:
            [
                Assignment("subject", WolfAuthAssignmentTargetKind.Subject, subjectId: subject.SubjectId),
                Assignment("group", WolfAuthAssignmentTargetKind.ExternalGroup, externalGroupKey: "reviewers"),
                Assignment("default", WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject),
                Assignment("bootstrap", WolfAuthAssignmentTargetKind.BootstrapAdministrator),
                Assignment("other", WolfAuthAssignmentTargetKind.Subject, subjectId: "other"),
                Assignment("missing-subject", WolfAuthAssignmentTargetKind.Subject),
                Assignment("missing-group", WolfAuthAssignmentTargetKind.ExternalGroup),
                Assignment("other-group", WolfAuthAssignmentTargetKind.ExternalGroup, externalGroupKey: "approvers"),
                Assignment("unknown", (WolfAuthAssignmentTargetKind)999)
            ]);

        var isKnown = await store.IsKnownSubjectAsync(subject);
        var assignments = await store.GetAssignmentsAsync(subject);

        Assert.True(isKnown);
        Assert.Contains(assignments, assignment => assignment.AssignmentId == "subject");
        Assert.Contains(assignments, assignment => assignment.AssignmentId == "group");
        Assert.Contains(assignments, assignment => assignment.AssignmentId == "default");
        Assert.DoesNotContain(assignments, assignment => assignment.AssignmentId == "bootstrap");
        Assert.DoesNotContain(assignments, assignment => assignment.AssignmentId == "other");
        Assert.DoesNotContain(assignments, assignment => assignment.AssignmentId == "missing-subject");
        Assert.DoesNotContain(assignments, assignment => assignment.AssignmentId == "missing-group");
        Assert.DoesNotContain(assignments, assignment => assignment.AssignmentId == "other-group");
        Assert.DoesNotContain(assignments, assignment => assignment.AssignmentId == "unknown");
    }

    /// <summary>
    /// Verifies builder helpers and null guards.
    /// </summary>
    [Fact]
    public void AuthorizationStoreBuilder_AddsSubjectsAndAssignments()
    {
        var subject = Subject("subject-1");
        var builder = new WolfAuthInMemoryAuthorizationStoreBuilder();

        builder.AddKnownSubject(subject.SubjectId);
        builder.AddKnownSubject(subject);
        builder.AddAssignment(Assignment("assignment", WolfAuthAssignmentTargetKind.Subject, subjectId: subject.SubjectId));
        var store = builder.Build();

        Assert.NotNull(store);
        Assert.Throws<ArgumentNullException>(() => builder.AddKnownSubject((WolfAuthSubject)null!));
        Assert.Throws<ArgumentNullException>(() => builder.AddAssignment(null!));
    }

    /// <summary>
    /// Verifies in-memory persistence store subject, assignment, and audit behavior.
    /// </summary>
    [Fact]
    public async Task PersistenceStore_SupportsSubjectsAssignmentsAuditAndCommit()
    {
        var subject = Subject("subject-1", groupIds: ["reviewers"]);
        var store = new WolfAuthInMemoryPersistenceStore(
            [new WolfAuthStoredSubject { Subject = subject }],
            [
                Assignment("group", WolfAuthAssignmentTargetKind.ExternalGroup, externalGroupKey: "reviewers"),
                Assignment("default", WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject),
                Assignment("bootstrap", WolfAuthAssignmentTargetKind.BootstrapAdministrator),
                Assignment("unknown", (WolfAuthAssignmentTargetKind)999),
                Assignment("missing-subject", WolfAuthAssignmentTargetKind.Subject),
                Assignment("missing-group", WolfAuthAssignmentTargetKind.ExternalGroup),
                Assignment("other-group", WolfAuthAssignmentTargetKind.ExternalGroup, externalGroupKey: "approvers")
            ]);

        await store.UpsertAssignmentAsync(Assignment("subject", WolfAuthAssignmentTargetKind.Subject, subjectId: subject.SubjectId));
        await store.AppendAsync(new WolfAuthAuditRecord
        {
            Action = WolfAuthAuditAction.AssignmentUpserted,
            SubjectId = subject.SubjectId
        });

        var allAssignments = await store.GetAssignmentsAsync();
        var matchingAssignments = await store.GetAssignmentsAsync(subject);
        var byExternalId = await store.FindSubjectByExternalIdAsync(subject.Provider, subject.ExternalUserId);
        var byOtherProvider = await store.FindSubjectByExternalIdAsync("other", subject.ExternalUserId);
        var commitCount = await store.CommitAsync();
        var auditRecords = await store.GetRecentAsync(0);

        Assert.Contains(allAssignments, assignment => assignment.AssignmentId == "subject");
        Assert.Contains(matchingAssignments, assignment => assignment.AssignmentId == "group");
        Assert.Contains(matchingAssignments, assignment => assignment.AssignmentId == "default");
        Assert.Contains(matchingAssignments, assignment => assignment.AssignmentId == "subject");
        Assert.DoesNotContain(matchingAssignments, assignment => assignment.AssignmentId == "bootstrap");
        Assert.DoesNotContain(matchingAssignments, assignment => assignment.AssignmentId == "unknown");
        Assert.DoesNotContain(matchingAssignments, assignment => assignment.AssignmentId == "missing-subject");
        Assert.DoesNotContain(matchingAssignments, assignment => assignment.AssignmentId == "missing-group");
        Assert.DoesNotContain(matchingAssignments, assignment => assignment.AssignmentId == "other-group");
        Assert.NotNull(byExternalId);
        Assert.Null(byOtherProvider);
        Assert.Equal(0, commitCount);
        Assert.Empty(auditRecords);
    }

    /// <summary>
    /// Verifies in-memory persistence store not-found paths and deactivation.
    /// </summary>
    [Fact]
    public async Task PersistenceStore_HandlesMissingValuesAndDeactivation()
    {
        var subject = Subject("subject-1");
        var store = new WolfAuthInMemoryPersistenceStore();

        var missingSubject = await store.FindSubjectAsync(subject.SubjectId);
        var missingExternalSubject = await store.FindSubjectByExternalIdAsync("test", "missing");
        var missingAssignment = await store.FindAssignmentAsync("missing");
        var removedMissing = await store.RemoveAssignmentAsync("missing");
        var deactivatedMissing = await store.DeactivateSubjectAsync(subject.SubjectId);
        var missingIsKnown = await store.IsKnownSubjectAsync(subject);

        await store.UpsertSubjectAsync(new WolfAuthStoredSubject { Subject = subject });
        var deactivated = await store.DeactivateSubjectAsync(subject.SubjectId);
        var isKnown = await store.IsKnownSubjectAsync(subject);

        Assert.Null(missingSubject);
        Assert.Null(missingExternalSubject);
        Assert.Null(missingAssignment);
        Assert.False(removedMissing);
        Assert.False(deactivatedMissing);
        Assert.False(missingIsKnown);
        Assert.True(deactivated);
        Assert.False(isKnown);
    }

    /// <summary>
    /// Verifies store null guards.
    /// </summary>
    [Fact]
    public async Task Stores_GuardNullInputs()
    {
        var authorizationStore = new WolfAuthInMemoryAuthorizationStore();
        var persistenceStore = new WolfAuthInMemoryPersistenceStore();

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authorizationStore.IsKnownSubjectAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authorizationStore.GetAssignmentsAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await persistenceStore.IsKnownSubjectAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await persistenceStore.GetAssignmentsAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await persistenceStore.UpsertSubjectAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await persistenceStore.UpsertAssignmentAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await persistenceStore.AppendAsync(null!));
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
    /// Creates a test assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment id.</param>
    /// <param name="targetKind">The target kind.</param>
    /// <param name="subjectId">The subject id.</param>
    /// <param name="externalGroupKey">The external group key.</param>
    /// <returns>The assignment.</returns>
    private static WolfAuthAssignment Assignment(
        string assignmentId,
        WolfAuthAssignmentTargetKind targetKind,
        WolfAuthSubjectId? subjectId = null,
        WolfAuthExternalGroupKey? externalGroupKey = null)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = targetKind,
            SubjectId = subjectId,
            ExternalGroupKey = externalGroupKey,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = "contracts.view"
        };
    }
}
