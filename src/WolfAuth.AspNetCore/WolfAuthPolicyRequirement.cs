using Microsoft.AspNetCore.Authorization;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Represents an ASP.NET Core authorization requirement for a WolfAuth policy.
/// </summary>
public sealed class WolfAuthPolicyRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthPolicyRequirement"/> class.
    /// </summary>
    /// <param name="policyKey">The required policy key.</param>
    /// <param name="scopeKey">The required scope key.</param>
    public WolfAuthPolicyRequirement(WolfAuthPolicyKey policyKey, WolfAuthScopeKey scopeKey)
    {
        PolicyKey = policyKey;
        ScopeKey = scopeKey;
    }

    /// <summary>
    /// Gets the required policy key.
    /// </summary>
    public WolfAuthPolicyKey PolicyKey { get; }

    /// <summary>
    /// Gets the required scope key.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; }
}
