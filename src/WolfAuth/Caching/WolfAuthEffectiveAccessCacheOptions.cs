namespace WolfAuth;

/// <summary>
/// Configures in-memory effective access caching.
/// </summary>
public sealed class WolfAuthEffectiveAccessCacheOptions
{
    /// <summary>
    /// Gets or sets the lifetime of a cached effective access snapshot.
    /// </summary>
    public TimeSpan TimeToLive { get; set; } = TimeSpan.FromMinutes(5);
}
