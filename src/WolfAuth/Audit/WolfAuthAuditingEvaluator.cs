namespace WolfAuth;

/// <summary>
/// Decorates an evaluator and emits audit records for authorization decisions.
/// </summary>
public sealed class WolfAuthAuditingEvaluator : IWolfAuthEvaluator
{
    private readonly IWolfAuthEvaluator _inner;
    private readonly IWolfAuthAuditStore _auditStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthAuditingEvaluator"/> class.
    /// </summary>
    /// <param name="inner">The evaluator to decorate.</param>
    /// <param name="auditStore">The audit store that receives decision records.</param>
    public WolfAuthAuditingEvaluator(IWolfAuthEvaluator inner, IWolfAuthAuditStore auditStore)
    {
        _inner = inner;
        _auditStore = auditStore;
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthEvaluationResult> CanAsync(
        WolfAuthEvaluationContext context,
        CancellationToken cancellationToken = default)
    {
        var result = await _inner.CanAsync(context, cancellationToken);
        await _auditStore.AppendAsync(CreateAuditRecord(context, result), cancellationToken);
        return result;
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        return _inner.GetEffectiveAccessAsync(subject, cancellationToken);
    }

    /// <summary>
    /// Creates an audit record for an authorization decision.
    /// </summary>
    /// <param name="context">The evaluation context.</param>
    /// <param name="result">The evaluation result.</param>
    /// <returns>The audit record to store.</returns>
    private static WolfAuthAuditRecord CreateAuditRecord(
        WolfAuthEvaluationContext context,
        WolfAuthEvaluationResult result)
    {
        var metadata = new Dictionary<string, string>
        {
            ["kind"] = context.Kind.ToString(),
            ["reason"] = result.Reason.ToString(),
            ["scope"] = context.ScopeKey.ToString()
        };

        if (context.PermissionKey is { } permissionKey)
        {
            metadata["permission"] = permissionKey.ToString();
        }

        if (context.PolicyKey is { } policyKey)
        {
            metadata["policy"] = policyKey.ToString();
        }

        return new WolfAuthAuditRecord
        {
            Action = WolfAuthAuditAction.AuthorizationEvaluated,
            SubjectId = context.Subject.SubjectId,
            Succeeded = result.IsAllowed,
            Message = result.Message,
            Metadata = metadata
        };
    }
}
