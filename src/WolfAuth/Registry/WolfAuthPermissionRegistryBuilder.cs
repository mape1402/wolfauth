namespace WolfAuth;

/// <summary>
/// Builds a host permission registry for WolfAuth.
/// </summary>
public sealed class WolfAuthPermissionRegistryBuilder
{
    private readonly Dictionary<WolfAuthPermissionKey, WolfAuthPermission> _permissions = [];
    private readonly Dictionary<WolfAuthRoleKey, WolfAuthRole> _roles = [];
    private readonly Dictionary<WolfAuthPolicyKey, WolfAuthPolicy> _policies = [];

    /// <summary>
    /// Registers a permission from simple metadata.
    /// </summary>
    /// <param name="key">The permission key.</param>
    /// <param name="displayName">The human-readable permission name.</param>
    /// <param name="description">The permission description.</param>
    /// <param name="category">The permission category.</param>
    /// <param name="riskLevel">The permission risk level.</param>
    /// <returns>The current builder.</returns>
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

    /// <summary>
    /// Registers a permission.
    /// </summary>
    /// <param name="permission">The permission to register.</param>
    /// <returns>The current builder.</returns>
    /// <exception cref="WolfAuthDuplicateRegistrationException">Thrown when a permission with the same key is already registered.</exception>
    public WolfAuthPermissionRegistryBuilder AddPermission(WolfAuthPermission permission)
    {
        if (!_permissions.TryAdd(permission.Key, permission))
        {
            throw new WolfAuthDuplicateRegistrationException("permission", permission.Key.ToString());
        }

        return this;
    }

    /// <summary>
    /// Registers a role from simple metadata and a role configuration delegate.
    /// </summary>
    /// <param name="key">The role key.</param>
    /// <param name="configure">The optional role configuration delegate.</param>
    /// <param name="displayName">The human-readable role name.</param>
    /// <param name="description">The role description.</param>
    /// <param name="isSystem">Whether the role is seeded or managed by the system.</param>
    /// <returns>The current builder.</returns>
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

    /// <summary>
    /// Registers a role.
    /// </summary>
    /// <param name="role">The role to register.</param>
    /// <returns>The current builder.</returns>
    /// <exception cref="WolfAuthDuplicateRegistrationException">Thrown when a role with the same key is already registered.</exception>
    public WolfAuthPermissionRegistryBuilder AddRole(WolfAuthRole role)
    {
        if (!_roles.TryAdd(role.Key, role))
        {
            throw new WolfAuthDuplicateRegistrationException("role", role.Key.ToString());
        }

        return this;
    }

    /// <summary>
    /// Registers a policy from simple metadata.
    /// </summary>
    /// <param name="key">The policy key.</param>
    /// <param name="displayName">The human-readable policy name.</param>
    /// <param name="description">The policy description.</param>
    /// <param name="riskLevel">The policy risk level.</param>
    /// <param name="requiredPermissions">Permissions generally required before policy-specific logic runs.</param>
    /// <returns>The current builder.</returns>
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

    /// <summary>
    /// Registers a policy.
    /// </summary>
    /// <param name="policy">The policy to register.</param>
    /// <returns>The current builder.</returns>
    /// <exception cref="WolfAuthDuplicateRegistrationException">Thrown when a policy with the same key is already registered.</exception>
    public WolfAuthPermissionRegistryBuilder AddPolicy(WolfAuthPolicy policy)
    {
        if (!_policies.TryAdd(policy.Key, policy))
        {
            throw new WolfAuthDuplicateRegistrationException("policy", policy.Key.ToString());
        }

        return this;
    }

    /// <summary>
    /// Builds an immutable permission registry.
    /// </summary>
    /// <returns>The built permission registry.</returns>
    public WolfAuthPermissionRegistry Build()
    {
        return new WolfAuthPermissionRegistry(
            new Dictionary<WolfAuthPermissionKey, WolfAuthPermission>(_permissions),
            new Dictionary<WolfAuthRoleKey, WolfAuthRole>(_roles),
            new Dictionary<WolfAuthPolicyKey, WolfAuthPolicy>(_policies));
    }
}

/// <summary>
/// Builds a role definition during registry configuration.
/// </summary>
public sealed class WolfAuthRoleBuilder
{
    private readonly List<WolfAuthPermissionGrant> _permissions = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthRoleBuilder"/> class.
    /// </summary>
    /// <param name="key">The role key.</param>
    public WolfAuthRoleBuilder(WolfAuthRoleKey key)
    {
        Key = key;
    }

    /// <summary>
    /// Gets the role key.
    /// </summary>
    public WolfAuthRoleKey Key { get; }

    /// <summary>
    /// Gets or sets the human-readable role name.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the role description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the role is seeded or managed by the system.
    /// </summary>
    public bool IsSystem { get; set; }

    /// <summary>
    /// Adds a permission grant to the role.
    /// </summary>
    /// <param name="permissionKey">The permission key to grant.</param>
    /// <param name="scopeKey">The scope where the grant applies, or global when omitted.</param>
    /// <returns>The current role builder.</returns>
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

    /// <summary>
    /// Builds the role definition.
    /// </summary>
    /// <returns>The built role definition.</returns>
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
