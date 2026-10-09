namespace WolfAuth.EntraIdWebSite;

/// <summary>
/// Defines Microsoft Entra ID configuration for the sample web site.
/// </summary>
internal sealed class EntraIdSampleOptions
{
    /// <summary>
    /// Gets the configuration section name.
    /// </summary>
    public const string SectionName = "EntraId";

    /// <summary>
    /// Gets or sets the Microsoft Entra ID tenant identifier.
    /// </summary>
    public string TenantId { get; set; } = "common";

    /// <summary>
    /// Gets or sets the application client identifier.
    /// </summary>
    public string ClientId { get; set; } = "00000000-0000-0000-0000-000000000000";

    /// <summary>
    /// Gets or sets the application client secret for confidential-client sign-in.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the OpenID Connect callback path.
    /// </summary>
    public string CallbackPath { get; set; } = "/signin-oidc";
}
