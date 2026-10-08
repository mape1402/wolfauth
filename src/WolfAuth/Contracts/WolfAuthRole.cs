namespace WolfAuth;

/// <summary>
/// Represents a host-defined role made of permission grants.
/// </summary>
public sealed record WolfAuthRole
{
    /// <summary>
    /// Gets the stable role key.
    /// </summary>
    public required WolfAuthRoleKey Key { get; init; }

    /// <summary>
    /// Gets the human-readable role name.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the role description.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// Gets a value indicating whether the role is seeded or managed by the system.
    /// </summary>
    public bool IsSystem { get; init; }

    /// <summary>
    /// Gets the permission grants included in the role.
    /// </summary>
    public IReadOnlyList<WolfAuthPermissionGrant> Permissions { get; init; } = [];
}
