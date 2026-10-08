using System.Security.Claims;

namespace WolfAuth.EntraIdWebSite;

/// <summary>
/// Provisions WolfAuth subjects after a successful Microsoft Entra ID sign-in.
/// </summary>
internal interface IEntraIdSignInProvisioner
{
    /// <summary>
    /// Provisions the signed-in principal and grants the sample site role.
    /// </summary>
    /// <param name="principal">The signed-in principal.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when provisioning has finished.</returns>
    Task ProvisionAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default);
}
