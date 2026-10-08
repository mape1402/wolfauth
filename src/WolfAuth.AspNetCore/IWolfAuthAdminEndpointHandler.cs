using Microsoft.AspNetCore.Http;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Handles WolfAuth administration endpoint requests.
/// </summary>
public interface IWolfAuthAdminEndpointHandler
{
    /// <summary>
    /// Gets effective access for a stored subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    Task<IResult> GetEffectiveAccessAsync(string subjectId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates an assignment.
    /// </summary>
    /// <param name="assignment">The assignment to validate.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    Task<IResult> ValidateAssignmentAsync(WolfAuthAssignment assignment, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores an assignment.
    /// </summary>
    /// <param name="request">The assignment request.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    Task<IResult> UpsertAssignmentAsync(WolfAuthAssignmentRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    Task<IResult> RemoveAssignmentAsync(string assignmentId, CancellationToken cancellationToken = default);
}
