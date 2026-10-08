using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace WolfAuth.EntityFrameworkCore;

/// <summary>
/// Implements WolfAuth persistence contracts with Entity Framework Core.
/// </summary>
public sealed class WolfAuthEntityFrameworkStore :
    IWolfAuthAuthorizationStore,
    IWolfAuthSubjectStore,
    IWolfAuthAssignmentStore,
    IWolfAuthAuditStore,
    IWolfAuthUnitOfWork
{
    private readonly WolfAuthDbContext _dbContext;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthEntityFrameworkStore"/> class.
    /// </summary>
    /// <param name="dbContext">The WolfAuth database context.</param>
    public WolfAuthEntityFrameworkStore(WolfAuthDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsKnownSubjectAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        return await _dbContext.Subjects.AnyAsync(
            storedSubject => storedSubject.SubjectId == subject.SubjectId.ToString() &&
                storedSubject.IsActive,
            cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var subjectId = subject.SubjectId.ToString();
        var groupKeys = subject.Groups
            .Select(group => group.ExternalGroupId.ToString())
            .ToArray();
        var assignments = await _dbContext.Assignments
            .Where(assignment =>
                (assignment.TargetKind == (int)WolfAuthAssignmentTargetKind.Subject &&
                    assignment.SubjectId == subjectId) ||
                (assignment.TargetKind == (int)WolfAuthAssignmentTargetKind.ExternalGroup &&
                    assignment.ExternalGroupKey != null &&
                    groupKeys.Contains(assignment.ExternalGroupKey)) ||
                assignment.TargetKind == (int)WolfAuthAssignmentTargetKind.DefaultAuthenticatedSubject)
            .ToArrayAsync(cancellationToken);

        return assignments.Select(ToAssignment).ToArray();
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        CancellationToken cancellationToken = default)
    {
        var assignments = await _dbContext.Assignments.ToArrayAsync(cancellationToken);
        return assignments.Select(ToAssignment).ToArray();
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthAssignment?> FindAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default)
    {
        var assignment = await _dbContext.Assignments.FindAsync([assignmentId], cancellationToken);
        return assignment is null ? null : ToAssignment(assignment);
    }

    /// <inheritdoc />
    public async ValueTask UpsertAssignmentAsync(
        WolfAuthAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);

        var entity = await _dbContext.Assignments.FindAsync([assignment.AssignmentId], cancellationToken);
        if (entity is null)
        {
            _dbContext.Assignments.Add(ToEntity(assignment));
            return;
        }

        CopyAssignment(assignment, entity);
    }

    /// <inheritdoc />
    public async ValueTask<bool> RemoveAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default)
    {
        var entity = await _dbContext.Assignments.FindAsync([assignmentId], cancellationToken);
        if (entity is null)
        {
            return false;
        }

        _dbContext.Assignments.Remove(entity);
        return true;
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthStoredSubject?> FindSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default)
    {
        var entity = await _dbContext.Subjects.FindAsync([subjectId.ToString()], cancellationToken);
        return entity is null ? null : ToStoredSubject(entity);
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthStoredSubject?> FindSubjectByExternalIdAsync(
        WolfAuthProviderKey provider,
        WolfAuthExternalUserId externalUserId,
        CancellationToken cancellationToken = default)
    {
        var providerValue = provider.ToString();
        var externalUserIdValue = externalUserId.ToString();
        var entity = await _dbContext.Subjects.FirstOrDefaultAsync(
            subject => subject.Provider == providerValue &&
                subject.ExternalUserId == externalUserIdValue,
            cancellationToken);

        return entity is null ? null : ToStoredSubject(entity);
    }

    /// <inheritdoc />
    public async ValueTask UpsertSubjectAsync(
        WolfAuthStoredSubject subject,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var entity = await _dbContext.Subjects.FindAsync(
            [subject.Subject.SubjectId.ToString()],
            cancellationToken);
        if (entity is null)
        {
            _dbContext.Subjects.Add(ToEntity(subject));
            return;
        }

        CopySubject(subject, entity);
    }

    /// <inheritdoc />
    public async ValueTask<bool> DeactivateSubjectAsync(
        WolfAuthSubjectId subjectId,
        CancellationToken cancellationToken = default)
    {
        var entity = await _dbContext.Subjects.FindAsync([subjectId.ToString()], cancellationToken);
        if (entity is null)
        {
            return false;
        }

        entity.IsActive = false;
        entity.UpdatedAt = DateTimeOffset.UtcNow;
        return true;
    }

    /// <inheritdoc />
    public ValueTask AppendAsync(
        WolfAuthAuditRecord record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();

        _dbContext.AuditRecords.Add(ToEntity(record));
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<WolfAuthAuditRecord>> GetRecentAsync(
        int take = 100,
        CancellationToken cancellationToken = default)
    {
        var entities = await _dbContext.AuditRecords
            .OrderByDescending(record => record.OccurredAt)
            .Take(Math.Max(0, take))
            .ToArrayAsync(cancellationToken);

        return entities.Select(ToAuditRecord).ToArray();
    }

    /// <inheritdoc />
    public async ValueTask<int> CommitAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Maps a subject entity into a stored subject.
    /// </summary>
    /// <param name="entity">The subject entity.</param>
    /// <returns>The mapped stored subject.</returns>
    private static WolfAuthStoredSubject ToStoredSubject(WolfAuthSubjectEntity entity)
    {
        return new WolfAuthStoredSubject
        {
            Subject = new WolfAuthSubject
            {
                SubjectId = entity.SubjectId,
                Provider = entity.Provider,
                ExternalUserId = entity.ExternalUserId,
                DisplayName = entity.DisplayName,
                Email = entity.Email,
                UserPrincipalName = entity.UserPrincipalName,
                Claims = Deserialize<WolfAuthClaim>(entity.ClaimsJson),
                Groups = Deserialize<WolfAuthExternalGroup>(entity.GroupsJson)
            },
            IsActive = entity.IsActive,
            CreatedAt = entity.CreatedAt,
            UpdatedAt = entity.UpdatedAt
        };
    }

    /// <summary>
    /// Maps a stored subject into an entity.
    /// </summary>
    /// <param name="subject">The stored subject.</param>
    /// <returns>The mapped subject entity.</returns>
    private static WolfAuthSubjectEntity ToEntity(WolfAuthStoredSubject subject)
    {
        var entity = new WolfAuthSubjectEntity();
        CopySubject(subject, entity);
        return entity;
    }

    /// <summary>
    /// Copies a stored subject into an existing entity.
    /// </summary>
    /// <param name="subject">The stored subject.</param>
    /// <param name="entity">The subject entity.</param>
    private static void CopySubject(WolfAuthStoredSubject subject, WolfAuthSubjectEntity entity)
    {
        entity.SubjectId = subject.Subject.SubjectId.ToString();
        entity.Provider = subject.Subject.Provider.ToString();
        entity.ExternalUserId = subject.Subject.ExternalUserId.ToString();
        entity.DisplayName = subject.Subject.DisplayName;
        entity.Email = subject.Subject.Email;
        entity.UserPrincipalName = subject.Subject.UserPrincipalName;
        entity.ClaimsJson = JsonSerializer.Serialize(subject.Subject.Claims);
        entity.GroupsJson = JsonSerializer.Serialize(subject.Subject.Groups);
        entity.IsActive = subject.IsActive;
        entity.CreatedAt = subject.CreatedAt;
        entity.UpdatedAt = subject.UpdatedAt;
    }

    /// <summary>
    /// Maps an assignment entity into a contract assignment.
    /// </summary>
    /// <param name="entity">The assignment entity.</param>
    /// <returns>The mapped assignment.</returns>
    private static WolfAuthAssignment ToAssignment(WolfAuthAssignmentEntity entity)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = entity.AssignmentId,
            TargetKind = (WolfAuthAssignmentTargetKind)entity.TargetKind,
            SubjectId = string.IsNullOrWhiteSpace(entity.SubjectId)
                ? (WolfAuthSubjectId?)null
                : new WolfAuthSubjectId(entity.SubjectId),
            ExternalGroupKey = string.IsNullOrWhiteSpace(entity.ExternalGroupKey)
                ? (WolfAuthExternalGroupKey?)null
                : new WolfAuthExternalGroupKey(entity.ExternalGroupKey),
            GrantKind = (WolfAuthAssignmentGrantKind)entity.GrantKind,
            PermissionKey = string.IsNullOrWhiteSpace(entity.PermissionKey)
                ? (WolfAuthPermissionKey?)null
                : new WolfAuthPermissionKey(entity.PermissionKey),
            RoleKey = string.IsNullOrWhiteSpace(entity.RoleKey)
                ? (WolfAuthRoleKey?)null
                : new WolfAuthRoleKey(entity.RoleKey),
            ScopeKey = string.IsNullOrWhiteSpace(entity.ScopeKey)
                ? WolfAuthScopeKey.Global
                : new WolfAuthScopeKey(entity.ScopeKey),
            Source = entity.Source
        };
    }

    /// <summary>
    /// Maps a contract assignment into an entity.
    /// </summary>
    /// <param name="assignment">The assignment to map.</param>
    /// <returns>The mapped assignment entity.</returns>
    private static WolfAuthAssignmentEntity ToEntity(WolfAuthAssignment assignment)
    {
        var entity = new WolfAuthAssignmentEntity();
        CopyAssignment(assignment, entity);
        return entity;
    }

    /// <summary>
    /// Copies a contract assignment into an existing entity.
    /// </summary>
    /// <param name="assignment">The assignment to copy.</param>
    /// <param name="entity">The destination entity.</param>
    private static void CopyAssignment(WolfAuthAssignment assignment, WolfAuthAssignmentEntity entity)
    {
        entity.AssignmentId = assignment.AssignmentId;
        entity.TargetKind = (int)assignment.TargetKind;
        entity.SubjectId = assignment.SubjectId?.ToString();
        entity.ExternalGroupKey = assignment.ExternalGroupKey?.ToString();
        entity.GrantKind = (int)assignment.GrantKind;
        entity.PermissionKey = assignment.PermissionKey?.ToString();
        entity.RoleKey = assignment.RoleKey?.ToString();
        entity.ScopeKey = assignment.ScopeKey.ToString();
        entity.Source = assignment.Source;
    }

    /// <summary>
    /// Maps an audit record into an entity.
    /// </summary>
    /// <param name="record">The audit record.</param>
    /// <returns>The mapped audit entity.</returns>
    private static WolfAuthAuditRecordEntity ToEntity(WolfAuthAuditRecord record)
    {
        return new WolfAuthAuditRecordEntity
        {
            AuditId = record.AuditId,
            Action = (int)record.Action,
            SubjectId = record.SubjectId?.ToString(),
            ActorSubjectId = record.ActorSubjectId?.ToString(),
            Succeeded = record.Succeeded,
            Message = record.Message,
            MetadataJson = JsonSerializer.Serialize(record.Metadata),
            OccurredAt = record.OccurredAt
        };
    }

    /// <summary>
    /// Maps an audit entity into an audit record.
    /// </summary>
    /// <param name="entity">The audit entity.</param>
    /// <returns>The mapped audit record.</returns>
    private static WolfAuthAuditRecord ToAuditRecord(WolfAuthAuditRecordEntity entity)
    {
        return new WolfAuthAuditRecord
        {
            AuditId = entity.AuditId,
            Action = (WolfAuthAuditAction)entity.Action,
            SubjectId = string.IsNullOrWhiteSpace(entity.SubjectId)
                ? (WolfAuthSubjectId?)null
                : new WolfAuthSubjectId(entity.SubjectId),
            ActorSubjectId = string.IsNullOrWhiteSpace(entity.ActorSubjectId)
                ? (WolfAuthSubjectId?)null
                : new WolfAuthSubjectId(entity.ActorSubjectId),
            Succeeded = entity.Succeeded,
            Message = entity.Message,
            Metadata = DeserializeDictionary(entity.MetadataJson),
            OccurredAt = entity.OccurredAt
        };
    }

    /// <summary>
    /// Deserializes a JSON array.
    /// </summary>
    /// <typeparam name="T">The array item type.</typeparam>
    /// <param name="json">The serialized JSON array.</param>
    /// <returns>The deserialized items.</returns>
    private static IReadOnlyList<T> Deserialize<T>(string json)
    {
        return JsonSerializer.Deserialize<IReadOnlyList<T>>(json) ?? [];
    }

    /// <summary>
    /// Deserializes a JSON dictionary.
    /// </summary>
    /// <param name="json">The serialized JSON dictionary.</param>
    /// <returns>The deserialized dictionary.</returns>
    private static IReadOnlyDictionary<string, string> DeserializeDictionary(string json)
    {
        return JsonSerializer.Deserialize<IReadOnlyDictionary<string, string>>(json) ??
            new Dictionary<string, string>();
    }
}
