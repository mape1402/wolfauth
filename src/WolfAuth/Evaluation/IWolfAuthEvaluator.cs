namespace WolfAuth;

/// <summary>
/// Evaluates WolfAuth authorization requests and expands effective access.
/// </summary>
public interface IWolfAuthEvaluator
{
    /// <summary>
    /// Evaluates whether the subject in the context can perform the requested permission or policy.
    /// </summary>
    /// <param name="context">The authorization evaluation context.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The authorization evaluation result.</returns>
    ValueTask<WolfAuthEvaluationResult> CanAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Expands the effective access available to a subject.
    /// </summary>
    /// <param name="subject">The subject whose access should be expanded.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The subject's effective access snapshot.</returns>
    ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Evaluates a single host-defined WolfAuth policy.
/// </summary>
public interface IWolfAuthPolicyEvaluator
{
    /// <summary>
    /// Gets the policy key handled by the evaluator.
    /// </summary>
    WolfAuthPolicyKey PolicyKey { get; }

    /// <summary>
    /// Evaluates the policy for the provided context.
    /// </summary>
    /// <param name="context">The authorization evaluation context.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The policy evaluation result.</returns>
    ValueTask<WolfAuthEvaluationResult> EvaluateAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken = default);
}
