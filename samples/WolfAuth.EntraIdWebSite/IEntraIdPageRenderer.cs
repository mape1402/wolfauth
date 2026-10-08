using System.Security.Claims;
using WolfAuth;

namespace WolfAuth.EntraIdWebSite;

/// <summary>
/// Renders simple HTML pages for the Entra ID web site sample.
/// </summary>
internal interface IEntraIdPageRenderer
{
    /// <summary>
    /// Renders the home page.
    /// </summary>
    /// <param name="principal">The current principal.</param>
    /// <returns>The HTML page.</returns>
    string Home(ClaimsPrincipal principal);

    /// <summary>
    /// Renders the signed-in dashboard page.
    /// </summary>
    /// <param name="principal">The current principal.</param>
    /// <param name="subject">The resolved WolfAuth subject.</param>
    /// <param name="access">The effective access snapshot.</param>
    /// <returns>The HTML page.</returns>
    string Dashboard(
        ClaimsPrincipal principal,
        WolfAuthSubject subject,
        WolfAuthEffectiveAccess access);
}
