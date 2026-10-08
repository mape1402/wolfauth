using System.Security.Claims;

namespace WolfAuth.Microsoft.EntraId;

/// <summary>
/// Maps Microsoft Entra ID principals into WolfAuth provisioning requests.
/// </summary>
public interface IWolfAuthEntraIdProvisioningMapper
{
    /// <summary>
    /// Creates a provisioning request from an Entra ID claims principal.
    /// </summary>
    /// <param name="principal">The claims principal to map.</param>
    /// <returns>The mapped provisioning request.</returns>
    WolfAuthProvisioningRequest CreateProvisioningRequest(ClaimsPrincipal principal);
}
