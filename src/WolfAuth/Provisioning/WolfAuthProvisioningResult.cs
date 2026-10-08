namespace WolfAuth;

/// <summary>
/// Represents the result of provisioning a subject.
/// </summary>
public sealed record WolfAuthProvisioningResult
{
    /// <summary>
    /// Gets the provisioned subject.
    /// </summary>
    public required WolfAuthSubject Subject { get; init; }

    /// <summary>
    /// Gets a value indicating whether the subject was newly created.
    /// </summary>
    public bool WasCreated { get; init; }

    /// <summary>
    /// Gets provisioning changes emitted by the operation.
    /// </summary>
    public IReadOnlyList<WolfAuthProvisioningChange> Changes { get; init; } = [];
}
