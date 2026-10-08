namespace WolfAuth.AspNetCore;

/// <summary>
/// Encodes and decodes WolfAuth ASP.NET Core authorization policy names.
/// </summary>
public sealed class WolfAuthPolicyNameCodec : IWolfAuthPolicyNameCodec
{
    private const string Prefix = "WolfAuth";
    private const string PermissionSegment = "Permission";
    private const string PolicySegment = "Policy";

    /// <inheritdoc />
    public string CreatePermissionPolicyName(
        WolfAuthPermissionKey permissionKey,
        WolfAuthScopeKey? scopeKey = null)
    {
        return CreatePolicyName(PermissionSegment, permissionKey.ToString(), scopeKey);
    }

    /// <inheritdoc />
    public string CreatePolicyPolicyName(
        WolfAuthPolicyKey policyKey,
        WolfAuthScopeKey? scopeKey = null)
    {
        return CreatePolicyName(PolicySegment, policyKey.ToString(), scopeKey);
    }

    /// <inheritdoc />
    public bool TryParse(string policyName, out WolfAuthPolicyName parsedPolicyName)
    {
        parsedPolicyName = new WolfAuthPolicyName
        {
            Kind = WolfAuthPolicyNameKind.Unknown
        };

        var segments = policyName.Split(':', StringSplitOptions.None);
        if (segments.Length < 3 ||
            !string.Equals(segments[0], Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var scope = segments.Length > 3 && !string.IsNullOrWhiteSpace(segments[3])
            ? new WolfAuthScopeKey(Uri.UnescapeDataString(segments[3]))
            : WolfAuthScopeKey.Global;

        if (string.Equals(segments[1], PermissionSegment, StringComparison.Ordinal))
        {
            parsedPolicyName = new WolfAuthPolicyName
            {
                Kind = WolfAuthPolicyNameKind.Permission,
                PermissionKey = new WolfAuthPermissionKey(Uri.UnescapeDataString(segments[2])),
                ScopeKey = scope
            };

            return true;
        }

        if (string.Equals(segments[1], PolicySegment, StringComparison.Ordinal))
        {
            parsedPolicyName = new WolfAuthPolicyName
            {
                Kind = WolfAuthPolicyNameKind.Policy,
                PolicyKey = new WolfAuthPolicyKey(Uri.UnescapeDataString(segments[2])),
                ScopeKey = scope
            };

            return true;
        }

        return false;
    }

    /// <summary>
    /// Creates an encoded policy name.
    /// </summary>
    /// <param name="segment">The policy kind segment.</param>
    /// <param name="key">The permission or policy key.</param>
    /// <param name="scopeKey">The optional scope key.</param>
    /// <returns>The encoded policy name.</returns>
    private static string CreatePolicyName(string segment, string key, WolfAuthScopeKey? scopeKey)
    {
        var encodedKey = Uri.EscapeDataString(key);
        var scope = scopeKey ?? WolfAuthScopeKey.Global;
        var encodedScope = Uri.EscapeDataString(scope.ToString());
        return $"{Prefix}:{segment}:{encodedKey}:{encodedScope}";
    }
}
