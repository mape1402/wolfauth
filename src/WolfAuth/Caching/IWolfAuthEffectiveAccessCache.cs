namespace WolfAuth;

/// <summary>
/// Caches effective access snapshots.
/// </summary>
public interface IWolfAuthEffectiveAccessCache
{
    /// <summary>
    /// Attempts to get a cached effective access snapshot.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="access">The cached effective access when one exists.</param>
    /// <returns><c>true</c> when a non-expired cache entry exists; otherwise, <c>false</c>.</returns>
    bool TryGet(WolfAuthSubjectId subjectId, out WolfAuthEffectiveAccess access);

    /// <summary>
    /// Stores an effective access snapshot.
    /// </summary>
    /// <param name="access">The effective access snapshot.</param>
    void Set(WolfAuthEffectiveAccess access);

    /// <summary>
    /// Invalidates a subject's cached effective access.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    void Invalidate(WolfAuthSubjectId subjectId);

    /// <summary>
    /// Invalidates all cached effective access snapshots.
    /// </summary>
    void InvalidateAll();
}
