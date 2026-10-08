using System.Security.Claims;

namespace WolfAuth.OpenIdConnect;

/// <summary>
/// Maps OpenID Connect principals into WolfAuth provisioning requests.
/// </summary>
public interface IWolfAuthOpenIdConnectProvisioningMapper
{
    /// <summary>
    /// Creates a provisioning request from a claims principal.
    /// </summary>
    /// <param name="principal">The claims principal to map.</param>
    /// <returns>The mapped provisioning request.</returns>
    WolfAuthProvisioningRequest CreateProvisioningRequest(ClaimsPrincipal principal);
}
