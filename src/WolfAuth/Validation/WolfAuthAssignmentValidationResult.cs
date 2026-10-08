namespace WolfAuth;

/// <summary>
/// Represents the result of validating a WolfAuth assignment.
/// </summary>
public sealed record WolfAuthAssignmentValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the assignment is valid.
    /// </summary>
    public bool IsValid => Errors.Count == 0;

    /// <summary>
    /// Gets validation errors.
    /// </summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <returns>A successful validation result.</returns>
    public static WolfAuthAssignmentValidationResult Success()
    {
        return new WolfAuthAssignmentValidationResult();
    }

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    /// <param name="errors">The validation errors.</param>
    /// <returns>A failed validation result.</returns>
    public static WolfAuthAssignmentValidationResult Failure(IEnumerable<string> errors)
    {
        return new WolfAuthAssignmentValidationResult
        {
            Errors = errors.ToArray()
        };
    }
}
