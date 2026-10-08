using System.Security.Claims;

namespace WolfAuth.MicrosoftEntraId;

/// <summary>
/// Configures Microsoft Entra ID claim mapping for WolfAuth provisioning.
/// </summary>
public sealed class WolfAuthEntraIdMappingOptions
{
    /// <summary>
    /// Gets or sets the provider key assigned to mapped Entra ID subjects.
    /// </summary>
    public WolfAuthProviderKey Provider { get; set; } = new("microsoft-entra-id");

    /// <summary>
    /// Gets or sets the claim type used as the Entra object identifier.
    /// </summary>
    public string ObjectIdClaimType { get; set; } = "oid";

    /// <summary>
    /// Gets or sets the fallback claim type used when the object identifier is absent.
    /// </summary>
    public string FallbackUserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;

    /// <summary>
    /// Gets or sets the claim type used as email.
    /// </summary>
    public string EmailClaimType { get; set; } = ClaimTypes.Email;

    /// <summary>
    /// Gets or sets the claim type used as display name.
    /// </summary>
    public string DisplayNameClaimType { get; set; } = "name";

    /// <summary>
    /// Gets or sets the claim type used as user principal name.
    /// </summary>
    public string UserPrincipalNameClaimType { get; set; } = "preferred_username";

    /// <summary>
    /// Gets Entra group claim types that should be mapped.
    /// </summary>
    public List<string> GroupClaimTypes { get; } = ["groups"];
}
