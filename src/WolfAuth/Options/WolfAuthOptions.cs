namespace WolfAuth;

/// <summary>
/// Configures core WolfAuth authorization behavior.
/// </summary>
public sealed class WolfAuthOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether authenticated subjects must be provisioned before receiving access.
    /// </summary>
    public bool RequireKnownSubject { get; set; } = true;

    /// <summary>
    /// Gets role keys granted to authenticated subjects when known subjects are not required.
    /// </summary>
    public List<WolfAuthRoleKey> DefaultAuthenticatedRoleKeys { get; } = [];

    /// <summary>
    /// Gets bootstrap administrator seed definitions.
    /// </summary>
    public List<WolfAuthBootstrapAdministrator> BootstrapAdministrators { get; } = [];
}

/// <summary>
/// Describes an administrator seed that should receive initial administrative access.
/// </summary>
public sealed record WolfAuthBootstrapAdministrator
{
    /// <summary>
    /// Gets the email address used to match the bootstrap administrator.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Gets the provider used to match the bootstrap administrator.
    /// </summary>
    public WolfAuthProviderKey? Provider { get; init; }

    /// <summary>
    /// Gets the external user identifier used to match the bootstrap administrator.
    /// </summary>
    public WolfAuthExternalUserId? ExternalUserId { get; init; }

    /// <summary>
    /// Gets the product-side subject identifier used to match the bootstrap administrator.
    /// </summary>
    public WolfAuthSubjectId? SubjectId { get; init; }

    /// <summary>
    /// Gets the role granted to the bootstrap administrator.
    /// </summary>
    public WolfAuthRoleKey RoleKey { get; init; } = WolfAuthRoleKey.Administrator;
}
