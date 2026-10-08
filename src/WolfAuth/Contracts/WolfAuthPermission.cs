namespace WolfAuth;

/// <summary>
/// Describes the operational sensitivity of a permission.
/// </summary>
public enum WolfAuthPermissionRiskLevel
{
    /// <summary>
    /// Low-risk access such as read-only or harmless actions.
    /// </summary>
    Low = 0,

    /// <summary>
    /// Medium-risk access that can change ordinary product data.
    /// </summary>
    Medium = 1,

    /// <summary>
    /// High-risk access that can affect important workflows or sensitive data.
    /// </summary>
    High = 2,

    /// <summary>
    /// Critical access that can affect security, production operations, or broad administration.
    /// </summary>
    Critical = 3
}

/// <summary>
/// Represents an atomic action that a host product can authorize.
/// </summary>
public sealed record WolfAuthPermission
{
    /// <summary>
    /// Gets the stable permission key.
    /// </summary>
    public required WolfAuthPermissionKey Key { get; init; }

    /// <summary>
    /// Gets the human-readable permission name.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the permission description.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// Gets the category used for grouping permissions in admin surfaces.
    /// </summary>
    public string? Category { get; init; }

    /// <summary>
    /// Gets the permission risk level.
    /// </summary>
    public WolfAuthPermissionRiskLevel RiskLevel { get; init; } = WolfAuthPermissionRiskLevel.Low;

    /// <summary>
    /// Gets arbitrary tags associated with the permission.
    /// </summary>
    public IReadOnlyList<string> Tags { get; init; } = [];
}

/// <summary>
/// Identifies where an effective permission grant came from.
/// </summary>
public enum WolfAuthGrantSource
{
    /// <summary>
    /// The permission was assigned directly to a subject.
    /// </summary>
    Direct = 0,

    /// <summary>
    /// The permission was granted through an internal role.
    /// </summary>
    Role = 1,

    /// <summary>
    /// The permission was granted through an external group mapping.
    /// </summary>
    ExternalGroup = 2,

    /// <summary>
    /// The permission was granted through bootstrap administrator seeding.
    /// </summary>
    Bootstrap = 3,

    /// <summary>
    /// The permission was granted through default authenticated access.
    /// </summary>
    Default = 4
}

/// <summary>
/// Represents a permission grant after role, group, default, or bootstrap expansion.
/// </summary>
public sealed record WolfAuthPermissionGrant
{
    /// <summary>
    /// Gets the granted permission key.
    /// </summary>
    public required WolfAuthPermissionKey PermissionKey { get; init; }

    /// <summary>
    /// Gets the scope where the grant applies.
    /// </summary>
    public WolfAuthScopeKey ScopeKey { get; init; } = WolfAuthScopeKey.Global;

    /// <summary>
    /// Gets the source that produced the grant.
    /// </summary>
    public WolfAuthGrantSource Source { get; init; } = WolfAuthGrantSource.Direct;

    /// <summary>
    /// Gets the role that produced the grant when the source is role-based.
    /// </summary>
    public WolfAuthRoleKey? RoleKey { get; init; }

    /// <summary>
    /// Gets the external group that produced the grant when the source is group-based.
    /// </summary>
    public WolfAuthExternalGroupKey? ExternalGroupKey { get; init; }
}
