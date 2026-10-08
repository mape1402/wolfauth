namespace WolfAuth;

/// <summary>
/// Validates assignment shape and registry references with secure defaults.
/// </summary>
public sealed class WolfAuthAssignmentValidator : IWolfAuthAssignmentValidator
{
    private readonly IWolfAuthPermissionRegistry _registry;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthAssignmentValidator"/> class.
    /// </summary>
    /// <param name="registry">The permission registry used to validate grants.</param>
    public WolfAuthAssignmentValidator(IWolfAuthPermissionRegistry registry)
    {
        _registry = registry;
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthAssignmentValidationResult> ValidateAsync(
        WolfAuthAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        cancellationToken.ThrowIfCancellationRequested();

        var errors = new List<string>();
        ValidateTarget(assignment, errors);
        ValidateGrant(assignment, errors);

        return ValueTask.FromResult(errors.Count == 0
            ? WolfAuthAssignmentValidationResult.Success()
            : WolfAuthAssignmentValidationResult.Failure(errors));
    }

    /// <summary>
    /// Validates the assignment target fields.
    /// </summary>
    /// <param name="assignment">The assignment to validate.</param>
    /// <param name="errors">The mutable validation error collection.</param>
    private static void ValidateTarget(WolfAuthAssignment assignment, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(assignment.AssignmentId))
        {
            errors.Add("AssignmentId is required.");
        }

        if (assignment.TargetKind == WolfAuthAssignmentTargetKind.Subject &&
            assignment.SubjectId is null)
        {
            errors.Add("Subject assignments require SubjectId.");
        }

        if (assignment.TargetKind == WolfAuthAssignmentTargetKind.ExternalGroup &&
            assignment.ExternalGroupKey is null)
        {
            errors.Add("External group assignments require ExternalGroupKey.");
        }
    }

    /// <summary>
    /// Validates the assignment grant fields and registry references.
    /// </summary>
    /// <param name="assignment">The assignment to validate.</param>
    /// <param name="errors">The mutable validation error collection.</param>
    private void ValidateGrant(WolfAuthAssignment assignment, List<string> errors)
    {
        if (assignment.GrantKind == WolfAuthAssignmentGrantKind.Permission)
        {
            if (assignment.PermissionKey is not { } permissionKey)
            {
                errors.Add("Permission assignments require PermissionKey.");
                return;
            }

            if (!_registry.TryGetPermission(permissionKey, out _))
            {
                errors.Add($"Permission '{permissionKey}' is not registered.");
            }

            return;
        }

        if (assignment.GrantKind == WolfAuthAssignmentGrantKind.Role)
        {
            if (assignment.RoleKey is not { } roleKey)
            {
                errors.Add("Role assignments require RoleKey.");
                return;
            }

            if (!_registry.TryGetRole(roleKey, out _))
            {
                errors.Add($"Role '{roleKey}' is not registered.");
            }
        }
    }
}
