using System.Security.Claims;

namespace WolfAuth;

/// <summary>
/// Configures how a <see cref="ClaimsPrincipal"/> is mapped into a <see cref="WolfAuthSubject"/>.
/// </summary>
public sealed class WolfAuthClaimsPrincipalMappingOptions
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthClaimsPrincipalMappingOptions"/> class with common .NET and OIDC claim mappings.
    /// </summary>
    public WolfAuthClaimsPrincipalMappingOptions()
    {
        SubjectIdClaimTypes.Add("sub");
        SubjectIdClaimTypes.Add(ClaimTypes.NameIdentifier);
        SubjectIdClaimTypes.Add("nameidentifier");
        SubjectIdClaimTypes.Add("oid");
        SubjectIdClaimTypes.Add("http://schemas.microsoft.com/identity/claims/objectidentifier");

        ExternalUserIdClaimTypes.Add("sub");
        ExternalUserIdClaimTypes.Add("oid");
        ExternalUserIdClaimTypes.Add("http://schemas.microsoft.com/identity/claims/objectidentifier");
        ExternalUserIdClaimTypes.Add(ClaimTypes.NameIdentifier);
        ExternalUserIdClaimTypes.Add("nameidentifier");

        DisplayNameClaimTypes.Add(ClaimTypes.Name);
        DisplayNameClaimTypes.Add("name");
        DisplayNameClaimTypes.Add("given_name");
        DisplayNameClaimTypes.Add("preferred_username");

        EmailClaimTypes.Add(ClaimTypes.Email);
        EmailClaimTypes.Add("email");
        EmailClaimTypes.Add("upn");
        EmailClaimTypes.Add("preferred_username");

        UserPrincipalNameClaimTypes.Add("upn");
        UserPrincipalNameClaimTypes.Add("preferred_username");
        UserPrincipalNameClaimTypes.Add(ClaimTypes.Email);
        UserPrincipalNameClaimTypes.Add("email");

        GroupClaimTypes.Add("groups");
        GroupClaimTypes.Add("group");
    }

    /// <summary>
    /// Gets or sets the provider used when no provider claim type is configured or no provider claim is present.
    /// </summary>
    public WolfAuthProviderKey DefaultProvider { get; set; } = new("default");

    /// <summary>
    /// Gets or sets the claim type used to resolve the provider key.
    /// </summary>
    public string? ProviderClaimType { get; set; }

    /// <summary>
    /// Gets candidate claim types used to resolve the product-side subject identifier.
    /// </summary>
    public List<string> SubjectIdClaimTypes { get; } = [];

    /// <summary>
    /// Gets candidate claim types used to resolve the provider-side user identifier.
    /// </summary>
    public List<string> ExternalUserIdClaimTypes { get; } = [];

    /// <summary>
    /// Gets candidate claim types used to resolve the display name.
    /// </summary>
    public List<string> DisplayNameClaimTypes { get; } = [];

    /// <summary>
    /// Gets candidate claim types used to resolve the email address.
    /// </summary>
    public List<string> EmailClaimTypes { get; } = [];

    /// <summary>
    /// Gets candidate claim types used to resolve the user principal name.
    /// </summary>
    public List<string> UserPrincipalNameClaimTypes { get; } = [];

    /// <summary>
    /// Gets claim types used to resolve external groups.
    /// </summary>
    public List<string> GroupClaimTypes { get; } = [];

    /// <summary>
    /// Gets or sets a value indicating whether all principal claims should be copied to the resolved subject.
    /// </summary>
    public bool IncludeAllClaims { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the subject id may fall back to the external user id when no dedicated subject id claim is found.
    /// </summary>
    public bool AllowSubjectIdFallbackToExternalUserId { get; set; } = true;
}
