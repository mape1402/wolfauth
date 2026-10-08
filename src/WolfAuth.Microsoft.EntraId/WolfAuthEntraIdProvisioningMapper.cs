using System.Security.Claims;

namespace WolfAuth.Microsoft.EntraId;

/// <summary>
/// Maps Microsoft Entra ID claims into WolfAuth provisioning requests.
/// </summary>
public sealed class WolfAuthEntraIdProvisioningMapper : IWolfAuthEntraIdProvisioningMapper
{
    private readonly WolfAuthEntraIdMappingOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthEntraIdProvisioningMapper"/> class.
    /// </summary>
    /// <param name="options">The Entra ID mapping options.</param>
    public WolfAuthEntraIdProvisioningMapper(WolfAuthEntraIdMappingOptions? options = null)
    {
        _options = options ?? new WolfAuthEntraIdMappingOptions();
    }

    /// <inheritdoc />
    public WolfAuthProvisioningRequest CreateProvisioningRequest(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var externalUserId = FindClaimValue(principal, _options.ObjectIdClaimType) ??
            FindClaimValue(principal, _options.FallbackUserIdClaimType);
        if (string.IsNullOrWhiteSpace(externalUserId))
        {
            throw new InvalidOperationException("The Entra ID principal does not contain an object identifier.");
        }

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
    /// Maps Entra ID group claims into WolfAuth external groups.
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
