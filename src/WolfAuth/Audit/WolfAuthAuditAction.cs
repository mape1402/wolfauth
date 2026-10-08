namespace WolfAuth;

/// <summary>
/// Identifies a WolfAuth action that can be audited.
/// </summary>
public enum WolfAuthAuditAction
{
    /// <summary>
    /// A subject was provisioned or updated.
    /// </summary>
    SubjectProvisioned = 0,

    /// <summary>
    /// A subject was deactivated.
    /// </summary>
    SubjectDeactivated = 1,

    /// <summary>
    /// An assignment was added or replaced.
    /// </summary>
    AssignmentUpserted = 2,

    /// <summary>
    /// An assignment was removed.
    /// </summary>
    AssignmentRemoved = 3,

    /// <summary>
    /// An authorization decision was evaluated.
    /// </summary>
    AuthorizationEvaluated = 4
}
