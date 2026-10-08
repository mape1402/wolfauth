namespace WolfAuth;

public sealed record WolfAuthPolicy
{
    public required WolfAuthPolicyKey Key { get; init; }

    public string? DisplayName { get; init; }

    public string? Description { get; init; }

    public WolfAuthPermissionRiskLevel RiskLevel { get; init; } = WolfAuthPermissionRiskLevel.Low;

    public IReadOnlyList<WolfAuthPermissionKey> RequiredPermissions { get; init; } = [];

    public IReadOnlyList<string> Tags { get; init; } = [];
}
