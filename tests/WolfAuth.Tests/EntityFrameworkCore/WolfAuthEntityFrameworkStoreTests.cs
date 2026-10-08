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
            SubjectId = subject.SubjectId
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
