namespace WolfAuth.EntityFrameworkCore;

/// <summary>
/// Represents a persisted WolfAuth audit record entity.
/// </summary>
public sealed class WolfAuthAuditRecordEntity
{
    /// <summary>
    /// Gets or sets the audit record identifier.
    /// </summary>
    public string AuditId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the audit action.
    /// </summary>
    public int Action { get; set; }

    /// <summary>
    /// Gets or sets the subject identifier.
    /// </summary>
    public string? SubjectId { get; set; }

    /// <summary>
    /// Gets or sets the actor subject identifier.
    /// </summary>
    public string? ActorSubjectId { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the audited action succeeded.
    /// </summary>
    public bool Succeeded { get; set; }

    /// <summary>
    /// Gets or sets the audit message.
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Gets or sets serialized metadata.
    /// </summary>
    public string MetadataJson { get; set; } = "{}";

    /// <summary>
    /// Gets or sets the timestamp when the action occurred.
    /// </summary>
    public DateTimeOffset OccurredAt { get; set; } = DateTimeOffset.UtcNow;
}
