namespace WolfAuth;

/// <summary>
/// Represents metadata for a host-defined authorization policy.
/// </summary>
public sealed record WolfAuthPolicy
{
    /// <summary>
    /// Gets the stable policy key.
    /// </summary>
    public required WolfAuthPolicyKey Key { get; init; }

    /// <summary>
    /// Gets the human-readable policy name.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the policy description.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// Gets the policy risk level.
    /// </summary>
    public WolfAuthPermissionRiskLevel RiskLevel { get; init; } = WolfAuthPermissionRiskLevel.Low;

    /// <summary>
    /// Gets permission keys that must usually be present before policy-specific logic runs.
    /// </summary>
    public IReadOnlyList<WolfAuthPermissionKey> RequiredPermissions { get; init; } = [];

    /// <summary>
    /// Gets arbitrary tags associated with the policy.
    /// </summary>
    public IReadOnlyList<string> Tags { get; init; } = [];
}
