namespace WolfAuth;

/// <summary>
/// Provides application-level administration operations for WolfAuth.
/// </summary>
public interface IWolfAuthAdministrationService
{
    /// <summary>
    /// Validates and stores an assignment.
    /// </summary>
    /// <param name="request">The assignment request.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The assignment operation result.</returns>
    ValueTask<WolfAuthAssignmentOperationResult> UpsertAssignmentAsync(
        WolfAuthAssignmentRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="actorSubjectId">The actor making the administrative change.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when an assignment was removed; otherwise, <c>false</c>.</returns>
    ValueTask<bool> RemoveAssignmentAsync(
        string assignmentId,
        WolfAuthSubjectId? actorSubjectId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets effective access for a subject.
    /// </summary>
    /// <param name="subject">The subject to inspect.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The subject's effective access snapshot.</returns>
    ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);
}
