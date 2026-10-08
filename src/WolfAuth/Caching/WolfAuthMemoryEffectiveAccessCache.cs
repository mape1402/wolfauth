using System.Collections.Concurrent;

namespace WolfAuth;

/// <summary>
/// Provides an in-memory effective access cache.
/// </summary>
public sealed class WolfAuthMemoryEffectiveAccessCache : IWolfAuthEffectiveAccessCache
{
    private readonly ConcurrentDictionary<WolfAuthSubjectId, CacheEntry> _entries = new();
    private readonly WolfAuthEffectiveAccessCacheOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthMemoryEffectiveAccessCache"/> class.
    /// </summary>
    /// <param name="options">The cache options.</param>
    public WolfAuthMemoryEffectiveAccessCache(WolfAuthEffectiveAccessCacheOptions? options = null)
    {
        _options = options ?? new WolfAuthEffectiveAccessCacheOptions();
    }

    /// <inheritdoc />
    public bool TryGet(WolfAuthSubjectId subjectId, out WolfAuthEffectiveAccess access)
    {
        if (_entries.TryGetValue(subjectId, out var entry) &&
            entry.ExpiresAt > DateTimeOffset.UtcNow)
        {
            access = entry.Access;
            return true;
        }

        _entries.TryRemove(subjectId, out _);
        access = null!;
        return false;
    }

    /// <inheritdoc />
    public void Set(WolfAuthEffectiveAccess access)
    {
        ArgumentNullException.ThrowIfNull(access);

        _entries[access.Subject.SubjectId] = new CacheEntry(
            access,
            DateTimeOffset.UtcNow.Add(_options.TimeToLive));
    }

    /// <inheritdoc />
    public void Invalidate(WolfAuthSubjectId subjectId)
    {
        _entries.TryRemove(subjectId, out _);
    }

    /// <inheritdoc />
    public void InvalidateAll()
    {
        _entries.Clear();
    }

    /// <summary>
    /// Represents an effective access cache entry.
    /// </summary>
    /// <param name="Access">The cached effective access snapshot.</param>
    /// <param name="ExpiresAt">The timestamp when the cache entry expires.</param>
    private sealed record CacheEntry(WolfAuthEffectiveAccess Access, DateTimeOffset ExpiresAt);
}
