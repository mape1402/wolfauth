namespace WolfAuth;

/// <summary>
/// Provides an in-memory authorization store for tests, demos, local development, and simple hosts.
/// </summary>
public sealed class WolfAuthInMemoryAuthorizationStore : IWolfAuthAuthorizationStore
{
    private readonly HashSet<WolfAuthSubjectId> _knownSubjectIds;
    private readonly IReadOnlyList<WolfAuthAssignment> _assignments;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthInMemoryAuthorizationStore"/> class.
    /// </summary>
    /// <param name="knownSubjectIds">Known subject identifiers.</param>
    /// <param name="assignments">Authorization assignments.</param>
    public WolfAuthInMemoryAuthorizationStore(
        IEnumerable<WolfAuthSubjectId>? knownSubjectIds = null,
        IEnumerable<WolfAuthAssignment>? assignments = null)
    {
        _knownSubjectIds = new HashSet<WolfAuthSubjectId>(knownSubjectIds ?? []);
        _assignments = assignments?.ToArray() ?? [];
    }

    /// <inheritdoc />
    public ValueTask<bool> IsKnownSubjectAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(subject);

        return ValueTask.FromResult(_knownSubjectIds.Contains(subject.SubjectId));
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(subject);

        var subjectGroupKeys = subject.Groups
            .Select(group => group.ExternalGroupId)
            .ToHashSet();

        var assignments = _assignments
            .Where(assignment => AppliesToSubject(assignment, subject, subjectGroupKeys))
            .ToArray();

        return ValueTask.FromResult<IReadOnlyList<WolfAuthAssignment>>(assignments);
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
