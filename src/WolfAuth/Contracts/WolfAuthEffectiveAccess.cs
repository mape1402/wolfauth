namespace WolfAuth;

/// <summary>
/// Represents the expanded access snapshot for a subject.
/// </summary>
public sealed record WolfAuthEffectiveAccess
{
    /// <summary>
    /// Gets the subject whose access was evaluated.
    /// </summary>
    public required WolfAuthSubject Subject { get; init; }

    /// <summary>
    /// Gets a value indicating whether the subject is known by the product authorization store.
    /// </summary>
    public bool IsKnownSubject { get; init; }

    /// <summary>
    /// Gets role keys that apply to the subject.
    /// </summary>
    public IReadOnlyList<WolfAuthRoleKey> RoleKeys { get; init; } = [];

    /// <summary>
    /// Gets the effective permission grants that apply to the subject.
    /// </summary>
    public IReadOnlyList<WolfAuthPermissionGrant> Permissions { get; init; } = [];

    /// <summary>
    /// Gets external groups considered during access expansion.
    /// </summary>
    public IReadOnlyList<WolfAuthExternalGroup> ExternalGroups { get; init; } = [];

    /// <summary>
    /// Gets the timestamp when the access snapshot was evaluated.
    /// </summary>
    public DateTimeOffset EvaluatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Determines whether the access snapshot includes a permission in the requested scope.
    /// </summary>
    /// <param name="permissionKey">The permission key to check.</param>
    /// <param name="scopeKey">The requested scope, or global when omitted.</param>
    /// <returns><c>true</c> when the permission is granted for the requested scope; otherwise, <c>false</c>.</returns>
    public bool HasPermission(WolfAuthPermissionKey permissionKey, WolfAuthScopeKey? scopeKey = null)
    {
        var requiredScope = scopeKey ?? WolfAuthScopeKey.Global;

        return Permissions.Any(permission =>
            permission.PermissionKey == permissionKey &&
            (permission.ScopeKey == WolfAuthScopeKey.Global || permission.ScopeKey == requiredScope));
    }
}
