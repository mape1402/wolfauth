namespace WolfAuth;

/// <summary>
/// Expands effective access for a normalized WolfAuth subject.
/// </summary>
public interface IWolfAuthEffectiveAccessResolver
{
    /// <summary>
    /// Expands effective access for the provided subject.
    /// </summary>
    /// <param name="subject">The subject whose access should be expanded.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The subject's effective access snapshot.</returns>
    ValueTask<WolfAuthEffectiveAccess> ResolveAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);
}
