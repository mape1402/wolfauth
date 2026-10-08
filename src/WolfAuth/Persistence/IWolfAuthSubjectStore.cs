namespace WolfAuth;

/// <summary>
/// Persists and retrieves WolfAuth subjects.
/// </summary>
public interface IWolfAuthSubjectStore
{
    /// <summary>
    /// Finds a subject by product-side identifier.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The stored subject when it exists; otherwise, <c>null</c>.</returns>
    ValueTask<WolfAuthStoredSubject?> FindSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a subject by provider-side identity.
    /// </summary>
    /// <param name="provider">The external identity provider.</param>
    /// <param name="externalUserId">The provider-side user identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The stored subject when it exists; otherwise, <c>null</c>.</returns>
    ValueTask<WolfAuthStoredSubject?> FindSubjectByExternalIdAsync(
        WolfAuthProviderKey provider,
        WolfAuthExternalUserId externalUserId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Inserts or replaces a subject.
    /// </summary>
    /// <param name="subject">The subject to store.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when the subject has been stored.</returns>
    ValueTask UpsertSubjectAsync(
        WolfAuthStoredSubject subject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a subject as inactive.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns><c>true</c> when the subject was found and deactivated; otherwise, <c>false</c>.</returns>
    ValueTask<bool> DeactivateSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default);
}
