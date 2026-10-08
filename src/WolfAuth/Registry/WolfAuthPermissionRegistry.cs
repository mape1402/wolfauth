namespace WolfAuth;

/// <summary>
/// Provides an immutable permission, role, and policy registry built from host registration.
/// </summary>
public sealed class WolfAuthPermissionRegistry : IWolfAuthPermissionRegistry
{
    private readonly IReadOnlyDictionary<WolfAuthPermissionKey, WolfAuthPermission> _permissions;
    private readonly IReadOnlyDictionary<WolfAuthRoleKey, WolfAuthRole> _roles;
    private readonly IReadOnlyDictionary<WolfAuthPolicyKey, WolfAuthPolicy> _policies;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthPermissionRegistry"/> class.
    /// </summary>
    /// <param name="permissions">The registered permissions indexed by key.</param>
    /// <param name="roles">The registered roles indexed by key.</param>
    /// <param name="policies">The registered policies indexed by key.</param>
    public WolfAuthPermissionRegistry(
        IReadOnlyDictionary<WolfAuthPermissionKey, WolfAuthPermission> permissions,
        IReadOnlyDictionary<WolfAuthRoleKey, WolfAuthRole> roles,
        IReadOnlyDictionary<WolfAuthPolicyKey, WolfAuthPolicy> policies)
    {
        _permissions = permissions;
        _roles = roles;
        _policies = policies;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<WolfAuthPermission> Permissions => _permissions.Values.ToArray();

    /// <inheritdoc />
    public IReadOnlyCollection<WolfAuthRole> Roles => _roles.Values.ToArray();

    /// <inheritdoc />
    public IReadOnlyCollection<WolfAuthPolicy> Policies => _policies.Values.ToArray();

    /// <inheritdoc />
    public bool TryGetPermission(WolfAuthPermissionKey key, out WolfAuthPermission? permission)
    {
        return _permissions.TryGetValue(key, out permission);
    }

    /// <inheritdoc />
    public bool TryGetRole(WolfAuthRoleKey key, out WolfAuthRole? role)
    {
        return _roles.TryGetValue(key, out role);
    }

    /// <inheritdoc />
    public bool TryGetPolicy(WolfAuthPolicyKey key, out WolfAuthPolicy? policy)
    {
        return _policies.TryGetValue(key, out policy);
    }
}
