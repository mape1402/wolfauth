namespace WolfAuth;

public sealed class WolfAuthPermissionRegistry : IWolfAuthPermissionRegistry
{
    private readonly IReadOnlyDictionary<WolfAuthPermissionKey, WolfAuthPermission> _permissions;
    private readonly IReadOnlyDictionary<WolfAuthRoleKey, WolfAuthRole> _roles;
    private readonly IReadOnlyDictionary<WolfAuthPolicyKey, WolfAuthPolicy> _policies;

    public WolfAuthPermissionRegistry(
        IReadOnlyDictionary<WolfAuthPermissionKey, WolfAuthPermission> permissions,
        IReadOnlyDictionary<WolfAuthRoleKey, WolfAuthRole> roles,
        IReadOnlyDictionary<WolfAuthPolicyKey, WolfAuthPolicy> policies)
    {
        _permissions = permissions;
        _roles = roles;
        _policies = policies;
    }

    public IReadOnlyCollection<WolfAuthPermission> Permissions => _permissions.Values.ToArray();

    public IReadOnlyCollection<WolfAuthRole> Roles => _roles.Values.ToArray();

    public IReadOnlyCollection<WolfAuthPolicy> Policies => _policies.Values.ToArray();

    public bool TryGetPermission(WolfAuthPermissionKey key, out WolfAuthPermission? permission)
    {
        return _permissions.TryGetValue(key, out permission);
    }

    public bool TryGetRole(WolfAuthRoleKey key, out WolfAuthRole? role)
    {
        return _roles.TryGetValue(key, out role);
    }

    public bool TryGetPolicy(WolfAuthPolicyKey key, out WolfAuthPolicy? policy)
    {
        return _policies.TryGetValue(key, out policy);
    }
}
