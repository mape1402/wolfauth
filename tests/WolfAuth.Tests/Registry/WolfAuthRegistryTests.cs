namespace WolfAuth.Tests.Registry;

/// <summary>
/// Tests the WolfAuth permission registry and builders.
/// </summary>
public sealed class WolfAuthRegistryTests
{
    /// <summary>
    /// Verifies that duplicate registrations throw stable registry exceptions.
    /// </summary>
    [Fact]
    public void Builder_ThrowsForDuplicateRegistrations()
    {
        var builder = new WolfAuthPermissionRegistryBuilder();

        builder.AddPermission("contracts.view");
        builder.AddRole("reader");
        builder.AddPolicy("contracts.policy");

        var duplicatePermission = Assert.Throws<WolfAuthDuplicateRegistrationException>(() =>
            builder.AddPermission("contracts.view"));
        var duplicateRole = Assert.Throws<WolfAuthDuplicateRegistrationException>(() =>
            builder.AddRole("reader"));
        var duplicatePolicy = Assert.Throws<WolfAuthDuplicateRegistrationException>(() =>
            builder.AddPolicy("contracts.policy"));

        Assert.Contains("permission", duplicatePermission.Message, StringComparison.Ordinal);
        Assert.Contains("role", duplicateRole.Message, StringComparison.Ordinal);
        Assert.Contains("policy", duplicatePolicy.Message, StringComparison.Ordinal);
        Assert.Equal("permission", duplicatePermission.Kind);
        Assert.Equal("contracts.view", duplicatePermission.Key);
        Assert.IsAssignableFrom<WolfAuthRegistryException>(duplicatePermission);
    }

    /// <summary>
    /// Verifies that registry lookup methods return registered values and miss unknown keys.
    /// </summary>
    [Fact]
    public void Registry_ReturnsCollectionsAndLookupResults()
    {
        var registry = new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.view", "View", "View contracts", "Contracts", WolfAuthPermissionRiskLevel.Low)
            .AddRole("reader", role =>
            {
                role.DisplayName = "Reader";
                role.Description = "Reads contracts";
                role.IsSystem = true;
                role.AddPermission("contracts.view", "environment:qa");
            })
            .AddPolicy(
                "contracts.policy",
                "Policy",
                "Policy description",
                WolfAuthPermissionRiskLevel.Medium,
                ["contracts.view"])
            .Build();

        var hasPermission = registry.TryGetPermission("contracts.view", out var permission);
        var hasRole = registry.TryGetRole("reader", out var role);
        var hasPolicy = registry.TryGetPolicy("contracts.policy", out var policy);
        var missingPermission = registry.TryGetPermission("contracts.missing", out var unknownPermission);

        Assert.True(hasPermission);
        Assert.True(hasRole);
        Assert.True(hasPolicy);
        Assert.False(missingPermission);
        Assert.Null(unknownPermission);
        Assert.Single(registry.Permissions);
        Assert.Single(registry.Roles);
        Assert.Single(registry.Policies);
        Assert.Equal("View", permission?.DisplayName);
        Assert.True(role?.IsSystem);
        Assert.Equal("environment:qa", role?.Permissions[0].ScopeKey.ToString());
        Assert.Equal("Policy", policy?.DisplayName);
    }
}
