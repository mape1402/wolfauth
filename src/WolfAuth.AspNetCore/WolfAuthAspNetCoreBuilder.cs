namespace WolfAuth.AspNetCore;

/// <summary>
/// Collects WolfAuth ASP.NET Core registration settings.
/// </summary>
public sealed class WolfAuthAspNetCoreBuilder
{
    /// <summary>
    /// Gets the core WolfAuth options.
    /// </summary>
    public WolfAuthOptions Options { get; } = new();

    /// <summary>
    /// Gets the claims principal mapping options.
    /// </summary>
    public WolfAuthClaimsPrincipalMappingOptions ClaimsMapping { get; } = new();

    /// <summary>
    /// Gets the permission registry builder.
    /// </summary>
    public WolfAuthPermissionRegistryBuilder Registry { get; } = new();

    /// <summary>
    /// Gets or sets the in-memory persistence store used by default registrations.
    /// </summary>
    public WolfAuthInMemoryPersistenceStore Store { get; set; } = new();

    /// <summary>
    /// Gets or sets a value indicating whether effective access should be cached.
    /// </summary>
    public bool EnableEffectiveAccessCache { get; set; } = true;

    /// <summary>
    /// Gets the effective access cache options.
    /// </summary>
    public WolfAuthEffectiveAccessCacheOptions CacheOptions { get; } = new();
}
