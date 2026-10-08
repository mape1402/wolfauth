using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Builds ASP.NET Core authorization policies from WolfAuth policy names.
/// </summary>
public sealed class WolfAuthAuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;
    private readonly IWolfAuthPolicyNameCodec _policyNameCodec;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthAuthorizationPolicyProvider"/> class.
    /// </summary>
    /// <param name="options">The ASP.NET Core authorization options.</param>
    /// <param name="policyNameCodec">The WolfAuth policy name codec.</param>
    public WolfAuthAuthorizationPolicyProvider(
        IOptions<AuthorizationOptions> options,
        IWolfAuthPolicyNameCodec policyNameCodec)
    {
        _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
        _policyNameCodec = policyNameCodec;
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
    {
        return _fallbackPolicyProvider.GetDefaultPolicyAsync();
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
    {
        return _fallbackPolicyProvider.GetFallbackPolicyAsync();
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!_policyNameCodec.TryParse(policyName, out var parsedPolicyName))
        {
            return _fallbackPolicyProvider.GetPolicyAsync(policyName);
        }

        var policy = parsedPolicyName.Kind switch
        {
            WolfAuthPolicyNameKind.Permission when parsedPolicyName.PermissionKey is { } permissionKey =>
                CreatePermissionPolicy(permissionKey, parsedPolicyName.ScopeKey),
            WolfAuthPolicyNameKind.Policy when parsedPolicyName.PolicyKey is { } policyKey =>
                CreatePolicyPolicy(policyKey, parsedPolicyName.ScopeKey),
            _ => null
        };

        return Task.FromResult(policy);
    }

    /// <summary>
    /// Creates an ASP.NET Core policy for a WolfAuth permission requirement.
    /// </summary>
    /// <param name="permissionKey">The permission key.</param>
    /// <param name="scopeKey">The scope key.</param>
    /// <returns>The ASP.NET Core authorization policy.</returns>
    private static AuthorizationPolicy CreatePermissionPolicy(
        WolfAuthPermissionKey permissionKey,
        WolfAuthScopeKey scopeKey)
    {
        return new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new WolfAuthPermissionRequirement(permissionKey, scopeKey))
            .Build();
    }

    /// <summary>
    /// Creates an ASP.NET Core policy for a WolfAuth policy requirement.
    /// </summary>
    /// <param name="policyKey">The policy key.</param>
    /// <param name="scopeKey">The scope key.</param>
    /// <returns>The ASP.NET Core authorization policy.</returns>
    private static AuthorizationPolicy CreatePolicyPolicy(
        WolfAuthPolicyKey policyKey,
        WolfAuthScopeKey scopeKey)
    {
        return new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new WolfAuthPolicyRequirement(policyKey, scopeKey))
            .Build();
    }
}
