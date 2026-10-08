namespace WolfAuth.AspNetCore;

/// <summary>
/// Resolves the current WolfAuth subject from the active HTTP request.
/// </summary>
public interface IWolfAuthCurrentSubjectAccessor
{
    /// <summary>
    /// Gets the current subject when the HTTP principal can be resolved.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The current subject when available; otherwise, <c>null</c>.</returns>
    ValueTask<WolfAuthSubject?> GetCurrentSubjectAsync(CancellationToken cancellationToken = default);
}
