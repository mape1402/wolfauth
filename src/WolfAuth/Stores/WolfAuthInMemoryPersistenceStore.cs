using System.Collections.Concurrent;

namespace WolfAuth;

/// <summary>
/// Provides a mutable in-memory store for authorization, administration, provisioning, and audit tests.
/// </summary>
public sealed class WolfAuthInMemoryPersistenceStore :
    IWolfAuthAuthorizationStore,
    IWolfAuthSubjectStore,
    IWolfAuthAssignmentStore,
    IWolfAuthAuditStore,
    IWolfAuthUnitOfWork
{
    private readonly ConcurrentDictionary<WolfAuthSubjectId, WolfAuthStoredSubject> _subjects = new();
    private readonly ConcurrentDictionary<string, WolfAuthAssignment> _assignments = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<WolfAuthAuditRecord> _auditRecords = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthInMemoryPersistenceStore"/> class.
    /// </summary>
    /// <param name="subjects">The subjects to seed.</param>
    /// <param name="assignments">The assignments to seed.</param>
    public WolfAuthInMemoryPersistenceStore(
        IEnumerable<WolfAuthStoredSubject>? subjects = null,
        IEnumerable<WolfAuthAssignment>? assignments = null)
    {
        foreach (var subject in subjects ?? [])
        {
            _subjects[subject.Subject.SubjectId] = subject;
        }

        foreach (var assignment in assignments ?? [])
        {
            _assignments[assignment.AssignmentId] = assignment;
        }
    }

    /// <inheritdoc />
    public ValueTask<bool> IsKnownSubjectAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(
            _subjects.TryGetValue(subject.SubjectId, out var storedSubject) &&
            storedSubject.IsActive);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        var subjectGroupKeys = subject.Groups
            .Select(group => group.ExternalGroupId)
            .ToHashSet();
        var assignments = _assignments.Values
            .Where(assignment => AppliesToSubject(assignment, subject, subjectGroupKeys))
            .ToArray();

        return ValueTask.FromResult<IReadOnlyList<WolfAuthAssignment>>(assignments);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlyList<WolfAuthAssignment>>(_assignments.Values.ToArray());
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthAssignment?> FindAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _assignments.TryGetValue(assignmentId, out var assignment);
        return ValueTask.FromResult(assignment);
    }

    /// <inheritdoc />
    public ValueTask UpsertAssignmentAsync(
        WolfAuthAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        cancellationToken.ThrowIfCancellationRequested();

        _assignments[assignment.AssignmentId] = assignment;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<bool> RemoveAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_assignments.TryRemove(assignmentId, out _));
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthStoredSubject?> FindSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _subjects.TryGetValue(subjectId, out var subject);
        return ValueTask.FromResult(subject);
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthStoredSubject?> FindSubjectByExternalIdAsync(
        WolfAuthProviderKey provider,
        WolfAuthExternalUserId externalUserId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var subject = _subjects.Values.FirstOrDefault(storedSubject =>
            storedSubject.Subject.Provider == provider &&
            storedSubject.Subject.ExternalUserId == externalUserId);

        return ValueTask.FromResult(subject);
    }

    /// <inheritdoc />
    public ValueTask UpsertSubjectAsync(
        WolfAuthStoredSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        cancellationToken.ThrowIfCancellationRequested();

        _subjects[subject.Subject.SubjectId] = subject;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<bool> DeactivateSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_subjects.TryGetValue(subjectId, out var subject))
        {
            return ValueTask.FromResult(false);
        }

        _subjects[subjectId] = subject with
        {
            IsActive = false,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        return ValueTask.FromResult(true);
    }

    /// <inheritdoc />
    public ValueTask AppendAsync(
        WolfAuthAuditRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();

        _auditRecords.Enqueue(record);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<WolfAuthAuditRecord>> GetRecentAsync(
        int take = 100,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var records = _auditRecords
            .Reverse()
            .Take(Math.Max(0, take))
            .ToArray();

        return ValueTask.FromResult<IReadOnlyList<WolfAuthAuditRecord>>(records);
    }

    /// <inheritdoc />
    public ValueTask<int> CommitAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(0);
    }

    /// <summary>
    /// Determines whether an assignment applies to the provided subject.
    /// </summary>
    /// <param name="assignment">The assignment to inspect.</param>
    /// <param name="subject">The subject to compare.</param>
    /// <param name="subjectGroupKeys">The subject's external group keys.</param>
    /// <returns><c>true</c> when the assignment applies to the subject; otherwise, <c>false</c>.</returns>
    private static bool AppliesToSubject(
        WolfAuthAssignment assignment,
        WolfAuthSubject subject,
        HashSet<WolfAuthExternalGroupKey> subjectGroupKeys)
    {
        return assignment.TargetKind switch
        {
            WolfAuthAssignmentTargetKind.Subject => assignment.SubjectId == subject.SubjectId,
            WolfAuthAssignmentTargetKind.ExternalGroup => assignment.ExternalGroupKey is { } groupKey &&
                subjectGroupKeys.Contains(groupKey),
            WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject => true,
            WolfAuthAssignmentTargetKind.BootstrapAdministrator => false,
            _ => false
        };
    }
}
