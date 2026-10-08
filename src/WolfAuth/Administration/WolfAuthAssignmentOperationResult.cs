namespace WolfAuth;

/// <summary>
/// Represents the result of an administrative assignment operation.
/// </summary>
public sealed record WolfAuthAssignmentOperationResult
{
    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool Succeeded => Validation is null || Validation.IsValid;

    /// <summary>
    /// Gets the assignment affected by the operation.
    /// </summary>
    public WolfAuthAssignment? Assignment { get; init; }

    /// <summary>
    /// Gets the validation result when the operation failed validation.
    /// </summary>
    public WolfAuthAssignmentValidationResult? Validation { get; init; }
}
