using Microsoft.EntityFrameworkCore;
using WolfAuth.EntityFrameworkCore;

namespace WolfAuth.Tests.EntityFrameworkCore;

/// <summary>
/// Tests the Entity Framework Core WolfAuth store.
/// </summary>
public sealed class WolfAuthEntityFrameworkStoreTests
{
    /// <summary>
    /// Verifies that the EF Core store persists subjects, assignments, and audit records.
    /// </summary>
    [Fact]
    public async Task EntityFrameworkStore_PersistsWolfAuthData()
    {
        await using var dbContext = CreateContext();
        var store = new WolfAuthEntityFrameworkStore(dbContext);
        var subject = new WolfAuthSubject
        {
            SubjectId = "subject-1",
            Provider = "test",
            ExternalUserId = "external-1",
            Groups =
            [
                new WolfAuthExternalGroup
                {
                    Provider = "test",
                    ExternalGroupId = "reviewers"
                }
            ]
        };

        await store.UpsertSubjectAsync(new WolfAuthStoredSubject { Subject = subject });
        await store.UpsertAssignmentAsync(new WolfAuthAssignment
        {
            AssignmentId = "assignment-1",
            TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
            ExternalGroupKey = "reviewers",
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = "contracts.events.view"
        });
        await store.AppendAsync(new WolfAuthAuditRecord
        {
            Action = WolfAuthAuditAction.AssignmentUpserted,
            SubjectId = subject.SubjectId,
            ActorSubjectId = "actor-1",
            Metadata = new Dictionary<string, string>
            {
                ["assignmentId"] = "assignment-1"
            }
        });
        await store.AppendAsync(new WolfAuthAuditRecord
        {
            Action = WolfAuthAuditAction.AuthorizationEvaluated,
            Message = "anonymous decision"
        });
        await store.CommitAsync();

        var storedSubject = await store.FindSubjectAsync(subject.SubjectId);
        var isKnown = await store.IsKnownSubjectAsync(subject);
        var assignments = await store.GetAssignmentsAsync(subject);
        var auditRecords = await store.GetRecentAsync();

        Assert.NotNull(storedSubject);
        Assert.True(isKnown);
        Assert.Contains(assignments, assignment => assignment.AssignmentId == "assignment-1");
        Assert.Contains(auditRecords, record => record.Action == WolfAuthAuditAction.AssignmentUpserted);
        Assert.Contains(auditRecords, record => record.ActorSubjectId?.ToString() == "actor-1");
    }

    /// <summary>
    /// Verifies EF Core store update and not-found paths.
    /// </summary>
    [Fact]
    public async Task EntityFrameworkStore_UpdatesAndHandlesMissingValues()
    {
        await using var dbContext = CreateContext();
        var store = new WolfAuthEntityFrameworkStore(dbContext);
        var subject = new WolfAuthSubject
        {
            SubjectId = "subject-1",
            Provider = "test",
            ExternalUserId = "external-1",
            Claims =
            [
                new WolfAuthClaim
                {
                    Type = "department",
                    Value = "security",
                    Issuer = "issuer"
                }
            ]
        };
        var assignment = new WolfAuthAssignment
        {
            AssignmentId = "assignment-1",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subject.SubjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Role,
            RoleKey = "reader",
            ScopeKey = "environment:qa",
            Source = "test"
        };

        await store.UpsertSubjectAsync(new WolfAuthStoredSubject { Subject = subject });
        await store.UpsertAssignmentAsync(assignment);
        await store.CommitAsync();

        await store.UpsertSubjectAsync(new WolfAuthStoredSubject
        {
            Subject = subject with { DisplayName = "Updated" },
            IsActive = true
        });
        await store.UpsertAssignmentAsync(assignment with { RoleKey = "operator" });
        await store.CommitAsync();

        var byExternalId = await store.FindSubjectByExternalIdAsync("test", "external-1");
        var missingExternalId = await store.FindSubjectByExternalIdAsync("test", "missing");
        var missingSubject = await store.FindSubjectAsync("missing");
        var foundAssignment = await store.FindAssignmentAsync("assignment-1");
        var missingAssignment = await store.FindAssignmentAsync("missing");
        var removedMissing = await store.RemoveAssignmentAsync("missing");
        var deactivatedMissing = await store.DeactivateSubjectAsync("missing");
        var deactivated = await store.DeactivateSubjectAsync(subject.SubjectId);
        await store.CommitAsync();
        var isKnown = await store.IsKnownSubjectAsync(subject);

        Assert.NotNull(byExternalId);
        Assert.Equal("Updated", byExternalId.Subject.DisplayName);
        Assert.Single(byExternalId.Subject.Claims);
        Assert.Null(missingExternalId);
        Assert.Null(missingSubject);
        Assert.NotNull(foundAssignment);
        Assert.Equal("operator", foundAssignment.RoleKey?.ToString());
        Assert.Null(missingAssignment);
        Assert.False(removedMissing);
        Assert.False(deactivatedMissing);
        Assert.True(deactivated);
        Assert.False(isKnown);
    }

    /// <summary>
    /// Verifies EF Core store removes existing assignments.
    /// </summary>
    [Fact]
    public async Task EntityFrameworkStore_RemovesExistingAssignment()
    {
        await using var dbContext = CreateContext();
        var store = new WolfAuthEntityFrameworkStore(dbContext);
        await store.UpsertAssignmentAsync(new WolfAuthAssignment
        {
            AssignmentId = "assignment-1",
            TargetKind = WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = "contracts.view"
        });
        await store.CommitAsync();

        var removed = await store.RemoveAssignmentAsync("assignment-1");
        await store.CommitAsync();
        var assignment = await store.FindAssignmentAsync("assignment-1");

        Assert.True(removed);
        Assert.Null(assignment);
    }

    /// <summary>
    /// Verifies EF Core store mapping for null serialized payloads and optional assignment values.
    /// </summary>
    [Fact]
    public async Task EntityFrameworkStore_MapsNullPayloadsAndOptionalValues()
    {
        await using var dbContext = CreateContext();
        dbContext.Subjects.Add(new WolfAuthSubjectEntity
        {
            SubjectId = "subject-1",
            Provider = "test",
            ExternalUserId = "external-1",
            ClaimsJson = "null",
            GroupsJson = "null"
        });
        dbContext.Assignments.Add(new WolfAuthAssignmentEntity
        {
            AssignmentId = "assignment-1",
            TargetKind = (int)WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
            GrantKind = (int)WolfAuthAssignmentGrantKind.Permission,
            ScopeKey = " "
        });
        dbContext.AuditRecords.Add(new WolfAuthAuditRecordEntity
        {
            AuditId = "audit-1",
            Action = (int)WolfAuthAuditAction.AuthorizationEvaluated,
            MetadataJson = "null",
            OccurredAt = DateTimeOffset.UtcNow
        });
        await dbContext.SaveChangesAsync();
        var store = new WolfAuthEntityFrameworkStore(dbContext);

        var subject = await store.FindSubjectAsync("subject-1");
        var assignments = await store.GetAssignmentsAsync();
        var auditRecords = await store.GetRecentAsync();

        Assert.NotNull(subject);
        Assert.Empty(subject.Subject.Claims);
        Assert.Empty(subject.Subject.Groups);
        var assignment = Assert.Single(assignments);
        Assert.Null(assignment.SubjectId);
        Assert.Null(assignment.ExternalGroupKey);
        Assert.Null(assignment.PermissionKey);
        Assert.Null(assignment.RoleKey);
        Assert.Equal(WolfAuthScopeKey.Global, assignment.ScopeKey);
        var auditRecord = Assert.Single(auditRecords);
        Assert.Null(auditRecord.SubjectId);
        Assert.Null(auditRecord.ActorSubjectId);
        Assert.Empty(auditRecord.Metadata);
    }

    /// <summary>
    /// Verifies EF Core store guards null inputs.
    /// </summary>
    [Fact]
    public async Task EntityFrameworkStore_GuardsNullInputs()
    {
        await using var dbContext = CreateContext();
        var store = new WolfAuthEntityFrameworkStore(dbContext);

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.IsKnownSubjectAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.GetAssignmentsAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.UpsertSubjectAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.UpsertAssignmentAsync(null!));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.AppendAsync(null!));
    }

    /// <summary>
    /// Creates an in-memory EF Core context.
    /// </summary>
    /// <returns>The created context.</returns>
    private static WolfAuthDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<WolfAuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("n"))
            .Options;

        return new WolfAuthDbContext(options);
    }
}
