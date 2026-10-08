using System.Security.Claims;

namespace WolfAuth.OpenIdConnect;

/// <summary>
/// Configures OpenID Connect claim mapping for WolfAuth provisioning.
/// </summary>
public sealed class WolfAuthOpenIdConnectMappingOptions
{
    /// <summary>
    /// Gets or sets the provider key assigned to mapped subjects.
    /// </summary>
    public WolfAuthProviderKey Provider { get; set; } = new("oidc");

    /// <summary>
    /// Gets or sets the claim type used as the external user identifier.
    /// </summary>
    public string ExternalUserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;

    /// <summary>
    /// Gets or sets the claim type used as email.
    /// </summary>
    public string EmailClaimType { get; set; } = ClaimTypes.Email;

    /// <summary>
    /// Gets or sets the claim type used as display name.
    /// </summary>
    public string DisplayNameClaimType { get; set; } = ClaimTypes.Name;

    /// <summary>
    /// Gets or sets the claim type used as user principal name.
    /// </summary>
    public string UserPrincipalNameClaimType { get; set; } = "preferred_username";

    /// <summary>
    /// Gets group claim types that should be mapped as external groups.
    /// </summary>
    public List<string> GroupClaimTypes { get; } = [ClaimTypes.GroupSid, "groups"];
}
