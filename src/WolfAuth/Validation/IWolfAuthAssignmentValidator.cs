namespace WolfAuth;

/// <summary>
/// Validates assignment shape and registry references before persistence.
/// </summary>
public interface IWolfAuthAssignmentValidator
{
    /// <summary>
    /// Validates an assignment.
    /// </summary>
    /// <param name="assignment">The assignment to validate.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The assignment validation result.</returns>
    ValueTask<WolfAuthAssignmentValidationResult> ValidateAsync(
        WolfAuthAssignment assignment,
        CancellationToken cancellationToken = default);
}
