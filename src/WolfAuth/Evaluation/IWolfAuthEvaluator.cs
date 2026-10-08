namespace WolfAuth;

public interface IWolfAuthEvaluator
{
    ValueTask<WolfAuthEvaluationResult> CanAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken = default);

    ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);
}

public interface IWolfAuthPolicyEvaluator
{
    WolfAuthPolicyKey PolicyKey { get; }

    ValueTask<WolfAuthEvaluationResult> EvaluateAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken = default);
}
