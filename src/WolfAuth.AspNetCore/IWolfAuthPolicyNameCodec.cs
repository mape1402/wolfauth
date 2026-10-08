namespace WolfAuth.AspNetCore;

/// <summary>
/// Encodes and decodes WolfAuth ASP.NET Core authorization policy names.
/// </summary>
public interface IWolfAuthPolicyNameCodec
{
    /// <summary>
    /// Creates a permission policy name.
    /// </summary>
    /// <param name="permissionKey">The permission key.</param>
    /// <param name="scopeKey">The optional scope key.</param>
    /// <returns>The encoded policy name.</returns>
    string CreatePermissionPolicyName(WolfAuthPermissionKey permissionKey, WolfAuthScopeKey? scopeKey = null);

    /// <summary>
    /// Creates a WolfAuth policy policy name.
    /// </summary>
    /// <param name="policyKey">The policy key.</param>
    /// <param name="scopeKey">The optional scope key.</param>
    /// <returns>The encoded policy name.</returns>
    string CreatePolicyPolicyName(WolfAuthPolicyKey policyKey, WolfAuthScopeKey? scopeKey = null);

    /// <summary>
    /// Attempts to parse a policy name.
    /// </summary>
    /// <param name="policyName">The policy name to parse.</param>
    /// <param name="parsedPolicyName">The parsed policy name when parsing succeeds.</param>
    /// <returns><c>true</c> when the policy name is a WolfAuth policy name; otherwise, <c>false</c>.</returns>
    bool TryParse(string policyName, out WolfAuthPolicyName parsedPolicyName);
}
