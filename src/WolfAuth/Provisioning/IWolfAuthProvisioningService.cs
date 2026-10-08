namespace WolfAuth;

/// <summary>
/// Provisions subjects and group snapshots into WolfAuth persistence.
/// </summary>
public interface IWolfAuthProvisioningService
{
    /// <summary>
    /// Inserts or updates a subject from an external provider snapshot.
    /// </summary>
    /// <param name="request">The provisioning request.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The provisioning result.</returns>
    ValueTask<WolfAuthProvisioningResult> UpsertSubjectAsync(
        WolfAuthProvisioningRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deactivates a subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when the subject was found and deactivated; otherwise, <c>false</c>.</returns>
    ValueTask<bool> DeactivateSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default);
}
