namespace WolfAuth;

/// <summary>
/// Represents an immutable audit entry emitted by WolfAuth.
/// </summary>
public sealed record WolfAuthAuditRecord
{
    /// <summary>
    /// Gets the audit record identifier.
    /// </summary>
    public string AuditId { get; init; } = Guid.NewGuid().ToString("n");

    /// <summary>
    /// Gets the audited action.
    /// </summary>
    public required WolfAuthAuditAction Action { get; init; }

    /// <summary>
    /// Gets the subject associated with the action when one exists.
    /// </summary>
    public WolfAuthSubjectId? SubjectId { get; init; }

    /// <summary>
    /// Gets the actor associated with the action when one exists.
    /// </summary>
    public WolfAuthSubjectId? ActorSubjectId { get; init; }

    /// <summary>
    /// Gets a value indicating whether the action succeeded.
    /// </summary>
    public bool Succeeded { get; init; } = true;

    /// <summary>
    /// Gets a human-readable action summary.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Gets structured metadata for diagnostics and compliance.
    /// </summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// Gets the audit timestamp.
    /// </summary>
    public DateTimeOffset OccurredAt { get; init; } = DateTimeOffset.UtcNow;
}
