namespace WolfAuth;

/// <summary>
/// Identifies why a WolfAuth subject resolution attempt failed.
/// </summary>
public enum WolfAuthSubjectResolutionFailureReason
{
    /// <summary>
    /// The supplied principal was null.
    /// </summary>
    InvalidPrincipal = 0,

    /// <summary>
    /// The principal is not authenticated.
    /// </summary>
    Unauthenticated = 1,

    /// <summary>
    /// The configured mapping could not resolve a subject identifier.
    /// </summary>
    MissingSubjectIdClaim = 2,

    /// <summary>
    /// The configured mapping could not resolve an external user identifier.
    /// </summary>
    MissingExternalUserIdClaim = 3,

    /// <summary>
    /// The configured mapping could not resolve an identity provider.
    /// </summary>
    MissingProvider = 4,

    /// <summary>
    /// The configured mapping produced an invalid value.
    /// </summary>
    InvalidMapping = 5
}

/// <summary>
/// Represents the outcome of resolving a normalized WolfAuth subject.
/// </summary>
public sealed record WolfAuthSubjectResolutionResult
{
    /// <summary>
    /// Gets a value indicating whether subject resolution succeeded.
    /// </summary>
    public required bool Succeeded { get; init; }

    /// <summary>
    /// Gets the resolved subject when resolution succeeded.
    /// </summary>
    public WolfAuthSubject? Subject { get; init; }

    /// <summary>
    /// Gets the stable failure reason when resolution failed.
    /// </summary>
    public WolfAuthSubjectResolutionFailureReason? FailureReason { get; init; }

    /// <summary>
    /// Gets an optional human-readable message for diagnostics.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Creates a successful subject resolution result.
    /// </summary>
    /// <param name="subject">The resolved subject.</param>
    /// <returns>A successful subject resolution result.</returns>
    public static WolfAuthSubjectResolutionResult Success(WolfAuthSubject subject)
    {
        return new WolfAuthSubjectResolutionResult
        {
            Succeeded = true,
            Subject = subject
        };
    }

    /// <summary>
    /// Creates a failed subject resolution result.
    /// </summary>
    /// <param name="failureReason">The stable failure reason.</param>
    /// <param name="message">An optional human-readable message.</param>
    /// <returns>A failed subject resolution result.</returns>
    public static WolfAuthSubjectResolutionResult Failure(
        WolfAuthSubjectResolutionFailureReason failureReason,
        string? message = null)
    {
        return new WolfAuthSubjectResolutionResult
        {
            Succeeded = false,
            FailureReason = failureReason,
            Message = message
        };
    }
}
