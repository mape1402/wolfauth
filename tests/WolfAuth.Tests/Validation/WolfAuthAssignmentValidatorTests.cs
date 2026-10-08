namespace WolfAuth.Tests.Validation;

/// <summary>
/// Tests assignment validation rules.
/// </summary>
public sealed class WolfAuthAssignmentValidatorTests
{
    /// <summary>
    /// Verifies that a valid direct permission assignment succeeds.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReturnsSuccess_ForValidPermissionAssignment()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var result = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "assignment-1",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = "subject-1",
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = "contracts.view"
        });

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    /// <summary>
    /// Verifies that a valid role assignment succeeds.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReturnsSuccess_ForValidRoleAssignment()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var result = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "assignment-1",
            TargetKind = WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
            GrantKind = WolfAuthAssignmentGrantKind.Role,
            RoleKey = "reader"
        });

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    /// <summary>
    /// Verifies that unknown grant kinds do not trigger permission or role reference validation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_SkipsGrantReferenceValidation_ForUnknownGrantKinds()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var result = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "assignment-1",
            TargetKind = WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
            GrantKind = (WolfAuthAssignmentGrantKind)999
        });

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    /// <summary>
    /// Verifies that invalid target shapes are reported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReturnsErrors_ForInvalidTargets()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var subjectResult = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "subject-assignment",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = "contracts.view"
        });
        var groupResult = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "group-assignment",
            TargetKind = WolfAuthAssignmentTargetKind.ExternalGroup,
            GrantKind = WolfAuthAssignmentGrantKind.Role,
            RoleKey = "reader"
        });

        Assert.Contains(subjectResult.Errors, error => error.Contains("SubjectId", StringComparison.Ordinal));
        Assert.Contains(groupResult.Errors, error => error.Contains("ExternalGroupKey", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that missing grant values are reported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReturnsErrors_ForMissingGrantValues()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var permissionResult = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "permission-assignment",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = "subject-1",
            GrantKind = WolfAuthAssignmentGrantKind.Permission
        });
        var roleResult = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "role-assignment",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = "subject-1",
            GrantKind = WolfAuthAssignmentGrantKind.Role
        });

        Assert.Contains(permissionResult.Errors, error => error.Contains("PermissionKey", StringComparison.Ordinal));
        Assert.Contains(roleResult.Errors, error => error.Contains("RoleKey", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that unknown registry references are reported.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReturnsErrors_ForUnknownRegistryReferences()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var permissionResult = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "permission-assignment",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = "subject-1",
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = "contracts.unknown"
        });
        var roleResult = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = "role-assignment",
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = "subject-1",
            GrantKind = WolfAuthAssignmentGrantKind.Role,
            RoleKey = "unknown-role"
        });

        Assert.Contains(permissionResult.Errors, error => error.Contains("contracts.unknown", StringComparison.Ordinal));
        Assert.Contains(roleResult.Errors, error => error.Contains("unknown-role", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that assignment id and null assignments are guarded.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_GuardsAssignmentShapeAndNull()
    {
        var validator = new WolfAuthAssignmentValidator(Registry());

        var result = await validator.ValidateAsync(new WolfAuthAssignment
        {
            AssignmentId = " ",
            TargetKind = WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject,
            GrantKind = WolfAuthAssignmentGrantKind.Role,
            RoleKey = "reader"
        });

        Assert.Contains(result.Errors, error => error.Contains("AssignmentId", StringComparison.Ordinal));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await validator.ValidateAsync(null!));
    }

    /// <summary>
    /// Creates the validation registry.
    /// </summary>
    /// <returns>The registry.</returns>
    private static IWolfAuthPermissionRegistry Registry()
    {
        return new WolfAuthPermissionRegistryBuilder()
            .AddPermission("contracts.view")
            .AddRole("reader", role => role.AddPermission("contracts.view"))
            .Build();
    }
}
