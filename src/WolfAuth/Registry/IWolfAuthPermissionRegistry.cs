namespace WolfAuth;

/// <summary>
/// Provides read access to the host-registered WolfAuth permission catalog.
/// </summary>
public interface IWolfAuthPermissionRegistry
{
    /// <summary>
    /// Gets registered permissions.
    /// </summary>
    IReadOnlyCollection<WolfAuthPermission> Permissions { get; }

    /// <summary>
    /// Gets registered roles.
    /// </summary>
    IReadOnlyCollection<WolfAuthRole> Roles { get; }

    /// <summary>
    /// Gets registered policies.
    /// </summary>
    IReadOnlyCollection<WolfAuthPolicy> Policies { get; }

    /// <summary>
    /// Attempts to get a registered permission by key.
    /// </summary>
    /// <param name="key">The permission key.</param>
    /// <param name="permission">The registered permission when found.</param>
    /// <returns><c>true</c> when the permission exists; otherwise, <c>false</c>.</returns>
    bool TryGetPermission(WolfAuthPermissionKey key, out WolfAuthPermission? permission);

    /// <summary>
    /// Attempts to get a registered role by key.
    /// </summary>
    /// <param name="key">The role key.</param>
    /// <param name="role">The registered role when found.</param>
    /// <returns><c>true</c> when the role exists; otherwise, <c>false</c>.</returns>
    bool TryGetRole(WolfAuthRoleKey key, out WolfAuthRole? role);

    /// <summary>
    /// Attempts to get a registered policy by key.
    /// </summary>
    /// <param name="key">The policy key.</param>
    /// <param name="policy">The registered policy when found.</param>
    /// <returns><c>true</c> when the policy exists; otherwise, <c>false</c>.</returns>
    bool TryGetPolicy(WolfAuthPolicyKey key, out WolfAuthPolicy? policy);
}
