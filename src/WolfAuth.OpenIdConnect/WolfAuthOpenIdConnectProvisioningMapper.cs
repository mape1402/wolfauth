using System.Security.Claims;

namespace WolfAuth.OpenIdConnect;

/// <summary>
/// Maps OpenID Connect claims into WolfAuth provisioning requests.
/// </summary>
public sealed class WolfAuthOpenIdConnectProvisioningMapper : IWolfAuthOpenIdConnectProvisioningMapper
{
    private readonly WolfAuthOpenIdConnectMappingOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthOpenIdConnectProvisioningMapper"/> class.
    /// </summary>
    /// <param name="options">The OpenID Connect mapping options.</param>
    public WolfAuthOpenIdConnectProvisioningMapper(WolfAuthOpenIdConnectMappingOptions? options = null)
    {
        _options = options ?? new WolfAuthOpenIdConnectMappingOptions();
    }

    /// <inheritdoc />
    public WolfAuthProvisioningRequest CreateProvisioningRequest(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var externalUserId = FindRequiredClaim(principal, _options.ExternalUserIdClaimType);

        return new WolfAuthProvisioningRequest
        {
            Provider = _options.Provider,
            ExternalUserId = externalUserId,
            DisplayName = FindClaimValue(principal, _options.DisplayNameClaimType),
            Email = FindClaimValue(principal, _options.EmailClaimType),
            UserPrincipalName = FindClaimValue(principal, _options.UserPrincipalNameClaimType),
            Claims = principal.Claims.Select(claim => new WolfAuthClaim
            {
                Type = claim.Type,
                Value = claim.Value,
                Issuer = claim.Issuer
            }).ToArray(),
            Groups = MapGroups(principal)
        };
    }

    /// <summary>
    /// Maps configured group claims into WolfAuth external groups.
    /// </summary>
    /// <param name="principal">The principal containing group claims.</param>
    /// <returns>The mapped external groups.</returns>
    private IReadOnlyList<WolfAuthExternalGroup> MapGroups(ClaimsPrincipal principal)
    {
        return principal.Claims
            .Where(claim => _options.GroupClaimTypes.Contains(claim.Type, StringComparer.Ordinal))
            .Select(claim => new WolfAuthExternalGroup
            {
                Provider = _options.Provider,
                ExternalGroupId = claim.Value,
                DisplayName = claim.Value
            })
            .Distinct()
            .ToArray();
    }

    /// <summary>
    /// Finds a required claim value.
    /// </summary>
    /// <param name="principal">The claims principal to inspect.</param>
    /// <param name="claimType">The required claim type.</param>
    /// <returns>The required claim value.</returns>
    private static WolfAuthExternalUserId FindRequiredClaim(ClaimsPrincipal principal, string claimType)
    {
        var value = FindClaimValue(principal, claimType);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Required claim '{claimType}' was not found.");
        }

        return new WolfAuthExternalUserId(value);
    }

    /// <summary>
    /// Finds the first claim value for a claim type.
    /// </summary>
    /// <param name="principal">The claims principal to inspect.</param>
    /// <param name="claimType">The claim type to find.</param>
    /// <returns>The claim value when one exists; otherwise, <c>null</c>.</returns>
    private static string? FindClaimValue(ClaimsPrincipal principal, string claimType)
    {
        return principal.FindFirst(claimType)?.Value;
    }
}
