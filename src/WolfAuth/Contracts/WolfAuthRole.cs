namespace WolfAuth;

public sealed record WolfAuthRole
{
    public required WolfAuthRoleKey Key { get; init; }

    public string? DisplayName { get; init; }

    public string? Description { get; init; }

    public bool IsSystem { get; init; }

    public IReadOnlyList<WolfAuthPermissionGrant> Permissions { get; init; } = [];
}
