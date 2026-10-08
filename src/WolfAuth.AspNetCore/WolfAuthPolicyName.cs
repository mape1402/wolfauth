namespace WolfAuth.AspNetCore;

/// <summary>
/// Represents a parsed WolfAuth ASP.NET Core policy name.
/// </summary>
public sealed record WolfAuthPolicyName
{
    /// <summary>
    /// Gets the policy name kind.
    /// </summary>
    public required WolfAuthPolicyNameKind Kind { get; init; }

    /// <summary>
    /// Gets the permission key for permission policy names.
    /// </summary>
    public WolfAuthPermissionKey? PermissionKey { get; init; }

    /// <summary>
    /// Gets the policy key for policy policy names.
    /// </summary>
    public WolfAuthPolicyKey? PolicyKey { get; init; }

    /// <summary>
    /// Gets the scope key for the authorization policy.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;
}
