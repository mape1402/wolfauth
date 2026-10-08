namespace WolfAuth;

/// <summary>
/// Represents an administrative request to upsert an assignment.
/// </summary>
public sealed record WolfAuthAssignmentRequest
{
    /// <summary>
    /// Gets the assignment to store.
    /// </summary>
    public required WolfAuthAssignment Assignment { get; init; }

    /// <summary>
    /// Gets the actor making the administrative change.
    /// </summary>
    public WolfAuthSubjectId? ActorSubjectId { get; init; }
}
