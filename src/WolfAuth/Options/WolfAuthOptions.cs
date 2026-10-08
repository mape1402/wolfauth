namespace WolfAuth;

public sealed class WolfAuthOptions
{
    public bool RequireKnownSubject { get; set; } = true;

    public List<WolfAuthRoleKey> DefaultAuthenticatedRoleKeys { get; } = [];

    public List<WolfAuthBootstrapAdministrator> BootstrapAdministrators { get; } = [];
}

public sealed record WolfAuthBootstrapAdministrator
{
    public string? Email { get; init; }

    public WolfAuthProviderKey? Provider { get; init; }

    public WolfAuthExternalUserId? ExternalUserId { get; init; }

    public WolfAuthSubjectId? SubjectId { get; init; }

    public WolfAuthRoleKey RoleKey { get; init; } = WolfAuthRoleKey.Administrator;
}
