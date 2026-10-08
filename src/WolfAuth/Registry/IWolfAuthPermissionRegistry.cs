namespace WolfAuth;

public interface IWolfAuthPermissionRegistry
{
    IReadOnlyCollection<WolfAuthPermission> Permissions { get; }

    IReadOnlyCollection<WolfAuthRole> Roles { get; }

    IReadOnlyCollection<WolfAuthPolicy> Policies { get; }

    bool TryGetPermission(WolfAuthPermissionKey key, out WolfAuthPermission? permission);

    bool TryGetRole(WolfAuthRoleKey key, out WolfAuthRole? role);

    bool TryGetPolicy(WolfAuthPolicyKey key, out WolfAuthPolicy? policy);
}
