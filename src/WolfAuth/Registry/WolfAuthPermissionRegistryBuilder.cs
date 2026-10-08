namespace WolfAuth;

public sealed class WolfAuthPermissionRegistryBuilder
{
    private readonly Dictionary<WolfAuthPermissionKey, WolfAuthPermission> _permissions = [];
    private readonly Dictionary<WolfAuthRoleKey, WolfAuthRole> _roles = [];
    private readonly Dictionary<WolfAuthPolicyKey, WolfAuthPolicy> _policies = [];

    public WolfAuthPermissionRegistryBuilder AddPermission(
        WolfAuthPermissionKey key,
        string? displayName = null,
        string? description = null,
        string? category = null,
        WolfAuthPermissionRiskLevel riskLevel = WolfAuthPermissionRiskLevel.Low)
    {
        return AddPermission(new WolfAuthPermission
        {
            Key = key,
            DisplayName = displayName,
            Description = description,
            Category = category,
            RiskLevel = riskLevel
        });
    }

    public WolfAuthPermissionRegistryBuilder AddPermission(WolfAuthPermission permission)
    {
        if (!_permissions.TryAdd(permission.Key, permission))
        {
            throw new WolfAuthDuplicateRegistrationException("permission", permission.Key.ToString());
        }

        return this;
    }

    public WolfAuthPermissionRegistryBuilder AddRole(
        WolfAuthRoleKey key,
        Action<WolfAuthRoleBuilder>? configure = null,
        string? displayName = null,
        string? description = null,
        bool isSystem = false)
    {
        var builder = new WolfAuthRoleBuilder(key)
        {
            DisplayName = displayName,
            Description = description,
            IsSystem = isSystem
        };

        configure?.Invoke(builder);

        return AddRole(builder.Build());
    }

    public WolfAuthPermissionRegistryBuilder AddRole(WolfAuthRole role)
    {
        if (!_roles.TryAdd(role.Key, role))
        {
            throw new WolfAuthDuplicateRegistrationException("role", role.Key.ToString());
        }

        return this;
    }

    public WolfAuthPermissionRegistryBuilder AddPolicy(
        WolfAuthPolicyKey key,
        string? displayName = null,
        string? description = null,
        WolfAuthPermissionRiskLevel riskLevel = WolfAuthPermissionRiskLevel.Low,
        IEnumerable<WolfAuthPermissionKey>? requiredPermissions = null)
    {
        return AddPolicy(new WolfAuthPolicy
        {
            Key = key,
            DisplayName = displayName,
            Description = description,
            RiskLevel = riskLevel,
            RequiredPermissions = requiredPermissions?.ToArray() ?? []
        });
    }

    public WolfAuthPermissionRegistryBuilder AddPolicy(WolfAuthPolicy policy)
    {
        if (!_policies.TryAdd(policy.Key, policy))
        {
            throw new WolfAuthDuplicateRegistrationException("policy", policy.Key.ToString());
        }

        return this;
    }

    public WolfAuthPermissionRegistry Build()
    {
        return new WolfAuthPermissionRegistry(
            new Dictionary<WolfAuthPermissionKey, WolfAuthPermission>(_permissions),
            new Dictionary<WolfAuthRoleKey, WolfAuthRole>(_roles),
            new Dictionary<WolfAuthPolicyKey, WolfAuthPolicy>(_policies));
    }
}

public sealed class WolfAuthRoleBuilder
{
    private readonly List<WolfAuthPermissionGrant> _permissions = [];

    public WolfAuthRoleBuilder(WolfAuthRoleKey key)
    {
        Key = key;
    }

    public WolfAuthRoleKey Key { get; }

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public bool IsSystem { get; set; }

    public WolfAuthRoleBuilder AddPermission(WolfAuthPermissionKey permissionKey, WolfAuthScopeKey? scopeKey = null)
    {
        _permissions.Add(new WolfAuthPermissionGrant
        {
            PermissionKey = permissionKey,
            ScopeKey = scopeKey ?? WolfAuthScopeKey.Global,
            Source = WolfAuthGrantSource.Role,
            RoleKey = Key
        });

        return this;
    }

    public WolfAuthRole Build()
    {
        return new WolfAuthRole
        {
            Key = Key,
            DisplayName = DisplayName,
            Description = Description,
            IsSystem = IsSystem,
            Permissions = _permissions.ToArray()
        };
    }
}
