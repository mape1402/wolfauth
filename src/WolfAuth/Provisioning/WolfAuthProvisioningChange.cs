namespace WolfAuth;

/// <summary>
/// Represents a provisioning change emitted by WolfAuth.
/// </summary>
public sealed record WolfAuthProvisioningChange
{
    /// <summary>
    /// Gets the change kind.
    /// </summary>
    public required WolfAuthProvisioningChangeKind Kind { get; init; }

    /// <summary>
    /// Gets the changed subject identifier.
    /// </summary>
    public required WolfAuthSubjectId SubjectId { get; init; }

    /// <summary>
    /// Gets a human-readable change summary.
    /// </summary>
    public string? Message { get; init; }
}
