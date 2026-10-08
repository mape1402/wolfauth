namespace WolfAuth;

/// <summary>
/// Decorates an effective access resolver with caching.
/// </summary>
public sealed class WolfAuthCachedEffectiveAccessResolver : IWolfAuthEffectiveAccessResolver
{
    private readonly IWolfAuthEffectiveAccessResolver _inner;
    private readonly IWolfAuthEffectiveAccessCache _cache;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthCachedEffectiveAccessResolver"/> class.
    /// </summary>
    /// <param name="inner">The resolver to decorate.</param>
    /// <param name="cache">The effective access cache.</param>
    public WolfAuthCachedEffectiveAccessResolver(
        IWolfAuthEffectiveAccessResolver inner,
        IWolfAuthEffectiveAccessCache cache)
    {
        _inner = inner;
        _cache = cache;
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthEffectiveAccess> ResolveAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        if (_cache.TryGet(subject.SubjectId, out var cachedAccess))
        {
            return cachedAccess;
        }

        var access = await _inner.ResolveAsync(subject, cancellationToken);
        _cache.Set(access);
        return access;
    }
}
