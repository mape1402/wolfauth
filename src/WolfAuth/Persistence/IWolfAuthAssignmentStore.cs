namespace WolfAuth;

/// <summary>
/// Persists and retrieves WolfAuth assignments.
/// </summary>
public interface IWolfAuthAssignmentStore
{
    /// <summary>
    /// Gets all assignments known by the store.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The stored assignments.</returns>
    ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds an assignment by identifier.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The assignment when it exists; otherwise, <c>null</c>.</returns>
    ValueTask<WolfAuthAssignment?> FindAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Inserts or replaces an assignment.
    /// </summary>
    /// <param name="assignment">The assignment to store.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when the assignment has been stored.</returns>
    ValueTask UpsertAssignmentAsync(
        WolfAuthAssignment assignment,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when an assignment was removed; otherwise, <c>false</c>.</returns>
    ValueTask<bool> RemoveAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default);
}
