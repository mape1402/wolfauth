using Microsoft.AspNetCore.Authorization;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Requires a WolfAuth permission for an ASP.NET Core endpoint or controller action.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class WolfAuthPermissionAttribute : AuthorizeAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthPermissionAttribute"/> class.
    /// </summary>
    /// <param name="permissionKey">The required permission key.</param>
    /// <param name="scopeKey">The optional required scope key.</param>
    public WolfAuthPermissionAttribute(string permissionKey, string? scopeKey = null)
    {
        PermissionKey = permissionKey;
        ScopeKey = scopeKey ?? WolfAuthScopeKey.Global.ToString();
        Policy = new WolfAuthPolicyNameCodec().CreatePermissionPolicyName(
            new WolfAuthPermissionKey(permissionKey),
            new WolfAuthScopeKey(ScopeKey));
    }

    /// <summary>
    /// Gets the required permission key.
    /// </summary>
    public string PermissionKey { get; }

    /// <summary>
    /// Gets the required scope key.
    /// </summary>
    public string ScopeKey { get; }
}
