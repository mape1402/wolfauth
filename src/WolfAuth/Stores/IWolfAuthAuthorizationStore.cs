namespace WolfAuth;

/// <summary>
/// Provides authorization data used by the core WolfAuth evaluator.
/// </summary>
public interface IWolfAuthAuthorizationStore
{
    /// <summary>
    /// Determines whether a subject is known by the product authorization store.
    /// </summary>
    /// <param name="subject">The subject to check.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when the subject is known; otherwise, <c>false</c>.</returns>
    ValueTask<bool> IsKnownSubjectAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets assignments relevant to a subject.
    /// </summary>
    /// <param name="subject">The subject whose assignments should be loaded.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>Assignments that can affect the subject.</returns>
    ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);
}
