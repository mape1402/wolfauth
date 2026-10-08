using Microsoft.AspNetCore.Authorization;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Requires a WolfAuth policy for an ASP.NET Core endpoint or controller action.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class WolfAuthPolicyAttribute : AuthorizeAttribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthPolicyAttribute"/> class.
    /// </summary>
    /// <param name="policyKey">The required WolfAuth policy key.</param>
    /// <param name="scopeKey">The optional required scope key.</param>
    public WolfAuthPolicyAttribute(string policyKey, string? scopeKey = null)
    {
        PolicyKey = policyKey;
        ScopeKey = scopeKey ?? WolfAuthScopeKey.Global.ToString();
        Policy = new WolfAuthPolicyNameCodec().CreatePolicyPolicyName(
            new WolfAuthPolicyKey(policyKey),
            new WolfAuthScopeKey(ScopeKey));
    }

    /// <summary>
    /// Gets the required WolfAuth policy key.
    /// </summary>
    public string PolicyKey { get; }

    /// <summary>
    /// Gets the required scope key.
    /// </summary>
    public string ScopeKey { get; }
}
