namespace WolfAuth;

/// <summary>
/// Provides default WolfAuth administration behavior.
/// </summary>
public sealed class WolfAuthAdministrationService : IWolfAuthAdministrationService
{
    private readonly IWolfAuthAssignmentStore _assignmentStore;
    private readonly IWolfAuthAssignmentValidator _assignmentValidator;
    private readonly IWolfAuthEvaluator _evaluator;
    private readonly IWolfAuthUnitOfWork? _unitOfWork;
    private readonly IWolfAuthAuditStore? _auditStore;
    private readonly IWolfAuthEffectiveAccessCache? _cache;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthAdministrationService"/> class.
    /// </summary>
    /// <param name="assignmentStore">The assignment store.</param>
    /// <param name="assignmentValidator">The assignment validator.</param>
    /// <param name="evaluator">The authorization evaluator.</param>
    /// <param name="unitOfWork">The optional unit of work used to commit changes.</param>
    /// <param name="auditStore">The optional audit store.</param>
    /// <param name="cache">The optional effective access cache.</param>
    public WolfAuthAdministrationService(
        IWolfAuthAssignmentStore assignmentStore,
        IWolfAuthAssignmentValidator assignmentValidator,
        IWolfAuthEvaluator evaluator,
        IWolfAuthUnitOfWork? unitOfWork = null,
        IWolfAuthAuditStore? auditStore = null,
        IWolfAuthEffectiveAccessCache? cache = null)
    {
        _assignmentStore = assignmentStore;
        _assignmentValidator = assignmentValidator;
        _evaluator = evaluator;
        _unitOfWork = unitOfWork;
        _auditStore = auditStore;
        _cache = cache;
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthAssignmentOperationResult> UpsertAssignmentAsync(
        WolfAuthAssignmentRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var validation = await _assignmentValidator.ValidateAsync(request.Assignment, cancellationToken);
        if (!validation.IsValid)
        {
            return new WolfAuthAssignmentOperationResult
            {
                Assignment = request.Assignment,
                Validation = validation
            };
        }

        await _assignmentStore.UpsertAssignmentAsync(request.Assignment, cancellationToken);
        await CommitAsync(cancellationToken);
        InvalidateAffectedSubject(request.Assignment);
        await AuditAssignmentAsync(
            WolfAuthAuditAction.AssignmentUpserted,
            request.Assignment,
            request.ActorSubjectId,
            cancellationToken);

        return new WolfAuthAssignmentOperationResult
        {
            Assignment = request.Assignment
        };
    }

    /// <inheritdoc />
    public async ValueTask<bool> RemoveAssignmentAsync(
        string assignmentId,
        WolfAuthSubjectId? actorSubjectId = null,
        CancellationToken cancellationToken = default)
    {
        var assignment = await _assignmentStore.FindAssignmentAsync(assignmentId, cancellationToken);
        var removed = await _assignmentStore.RemoveAssignmentAsync(assignmentId, cancellationToken);
        if (!removed)
        {
            return false;
        }

        await CommitAsync(cancellationToken);

        if (assignment is not null)
        {
            InvalidateAffectedSubject(assignment);
            await AuditAssignmentAsync(
                WolfAuthAuditAction.AssignmentRemoved,
                assignment,
                actorSubjectId,
                cancellationToken);
        }

        return true;
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        return _evaluator.GetEffectiveAccessAsync(subject, cancellationToken);
    }

    /// <summary>
    /// Commits pending changes when a unit of work is available.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when changes have been committed.</returns>
    private ValueTask<int> CommitAsync(CancellationToken cancellationToken)
    {
        return _unitOfWork?.CommitAsync(cancellationToken) ?? ValueTask.FromResult(0);
    }

    /// <summary>
    /// Invalidates cached effective access for subject assignments.
    /// </summary>
    /// <param name="assignment">The assignment that changed.</param>
    private void InvalidateAffectedSubject(WolfAuthAssignment assignment)
    {
        if (assignment.SubjectId is { } subjectId)
        {
            _cache?.Invalidate(subjectId);
        }
        else
        {
            _cache?.InvalidateAll();
        }
    }

    /// <summary>
    /// Writes an assignment audit record when an audit store is available.
    /// </summary>
    /// <param name="action">The audit action.</param>
    /// <param name="assignment">The changed assignment.</param>
    /// <param name="actorSubjectId">The actor making the change.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when the audit record has been appended.</returns>
    private ValueTask AuditAssignmentAsync(
        WolfAuthAuditAction action,
        WolfAuthAssignment assignment,
        WolfAuthSubjectId? actorSubjectId,
        CancellationToken cancellationToken)
    {
        if (_auditStore is null)
        {
            return ValueTask.CompletedTask;
        }

        return _auditStore.AppendAsync(new WolfAuthAuditRecord
        {
            Action = action,
            SubjectId = assignment.SubjectId,
            ActorSubjectId = actorSubjectId,
            Message = assignment.AssignmentId,
            Metadata = new Dictionary<string, string>
            {
                ["assignmentId"] = assignment.AssignmentId,
                ["targetKind"] = assignment.TargetKind.ToString(),
                ["grantKind"] = assignment.GrantKind.ToString()
            }
        }, cancellationToken);
    }
}
