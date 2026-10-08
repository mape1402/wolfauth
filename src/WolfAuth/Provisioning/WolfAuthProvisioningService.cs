namespace WolfAuth;

/// <summary>
/// Provides idempotent subject provisioning.
/// </summary>
public sealed class WolfAuthProvisioningService : IWolfAuthProvisioningService
{
    private readonly IWolfAuthSubjectStore _subjectStore;
    private readonly IWolfAuthUnitOfWork? _unitOfWork;
    private readonly IWolfAuthAuditStore? _auditStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthProvisioningService"/> class.
    /// </summary>
    /// <param name="subjectStore">The subject store.</param>
    /// <param name="unitOfWork">The optional unit of work used to commit changes.</param>
    /// <param name="auditStore">The optional audit store.</param>
    public WolfAuthProvisioningService(
        IWolfAuthSubjectStore subjectStore,
        IWolfAuthUnitOfWork? unitOfWork = null,
        IWolfAuthAuditStore? auditStore = null)
    {
        _subjectStore = subjectStore;
        _unitOfWork = unitOfWork;
        _auditStore = auditStore;
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthProvisioningResult> UpsertSubjectAsync(
        WolfAuthProvisioningRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var existing = request.SubjectId is { } requestedSubjectId
            ? await _subjectStore.FindSubjectAsync(requestedSubjectId, cancellationToken)
            : await _subjectStore.FindSubjectByExternalIdAsync(
                request.Provider,
                request.ExternalUserId,
                cancellationToken);
        var subjectId = existing?.Subject.SubjectId ??
            request.SubjectId ??
            CreateSubjectId(request.Provider, request.ExternalUserId);
        var now = DateTimeOffset.UtcNow;
        var subject = new WolfAuthSubject
        {
            SubjectId = subjectId,
            Provider = request.Provider,
            ExternalUserId = request.ExternalUserId,
            DisplayName = request.DisplayName,
            Email = request.Email,
            UserPrincipalName = request.UserPrincipalName,
            Claims = request.Claims,
            Groups = request.Groups
        };
        var storedSubject = new WolfAuthStoredSubject
        {
            Subject = subject,
            IsActive = request.IsActive,
            CreatedAt = existing?.CreatedAt ?? now,
            UpdatedAt = now
        };

        await _subjectStore.UpsertSubjectAsync(storedSubject, cancellationToken);
        await CommitAsync(cancellationToken);

        var change = new WolfAuthProvisioningChange
        {
            Kind = existing is null
                ? WolfAuthProvisioningChangeKind.SubjectCreated
                : WolfAuthProvisioningChangeKind.SubjectUpdated,
            SubjectId = subjectId,
            Message = existing is null ? "Subject created." : "Subject updated."
        };

        await AuditAsync(change, cancellationToken);

        return new WolfAuthProvisioningResult
        {
            Subject = subject,
            WasCreated = existing is null,
            Changes = [change]
        };
    }

    /// <inheritdoc />
    public async ValueTask<bool> DeactivateSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default)
    {
        var deactivated = await _subjectStore.DeactivateSubjectAsync(subjectId, cancellationToken);
        if (!deactivated)
        {
            return false;
        }

        await CommitAsync(cancellationToken);
        await AuditAsync(new WolfAuthProvisioningChange
        {
            Kind = WolfAuthProvisioningChangeKind.SubjectDeactivated,
            SubjectId = subjectId,
            Message = "Subject deactivated."
        }, cancellationToken);

        return true;
    }

    /// <summary>
    /// Creates a deterministic subject identifier from an external identity.
    /// </summary>
    /// <param name="provider">The identity provider key.</param>
    /// <param name="externalUserId">The external user identifier.</param>
    /// <returns>The deterministic subject identifier.</returns>
    private static WolfAuthSubjectId CreateSubjectId(
        WolfAuthProviderKey provider,
        WolfAuthExternalUserId externalUserId)
    {
        return new WolfAuthSubjectId($"{provider}:{externalUserId}");
    }

    /// <summary>
    /// Commits pending store changes when a unit of work is available.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when the unit of work has committed.</returns>
    private ValueTask<int> CommitAsync(CancellationToken cancellationToken)
    {
        return _unitOfWork?.CommitAsync(cancellationToken) ?? ValueTask.FromResult(0);
    }

    /// <summary>
    /// Writes a provisioning audit record when an audit store is available.
    /// </summary>
    /// <param name="change">The provisioning change to audit.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A task that completes when the audit record has been appended.</returns>
    private ValueTask AuditAsync(
        WolfAuthProvisioningChange change,
        CancellationToken cancellationToken)
    {
        if (_auditStore is null)
        {
            return ValueTask.CompletedTask;
        }

        return _auditStore.AppendAsync(new WolfAuthAuditRecord
        {
            Action = change.Kind == WolfAuthProvisioningChangeKind.SubjectDeactivated
                ? WolfAuthAuditAction.SubjectDeactivated
                : WolfAuthAuditAction.SubjectProvisioned,
            SubjectId = change.SubjectId,
            Message = change.Message
        }, cancellationToken);
    }
}
