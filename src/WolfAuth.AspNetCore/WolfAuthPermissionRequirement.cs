using Microsoft.AspNetCore.Authorization;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Represents an ASP.NET Core authorization requirement for a WolfAuth permission.
/// </summary>
public sealed class WolfAuthPermissionRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthPermissionRequirement"/> class.
    /// </summary>
    /// <param name="permissionKey">The required permission key.</param>
    /// <param name="scopeKey">The required scope key.</param>
    public WolfAuthPermissionRequirement(
        WolfAuthPermissionKey permissionKey,
        WolfAuthScopeKey scopeKey)
    {
        PermissionKey = permissionKey;
        ScopeKey = scopeKey;
    }

    /// <summary>
    /// Gets the required permission key.
    /// </summary>
    public WolfAuthPermissionKey PermissionKey { get; }

    /// <summary>
    /// Gets the required scope key.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; }
}
