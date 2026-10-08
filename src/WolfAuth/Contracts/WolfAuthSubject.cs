namespace WolfAuth;

public sealed record WolfAuthClaim
{
    public required string Type { get; init; }

    public string? Value { get; init; }

    public string? Issuer { get; init; }
}

public sealed record WolfAuthExternalGroup
{
    public required WolfAuthProviderKey Provider { get; init; }

    public required WolfAuthExternalGroupKey ExternalGroupId { get; init; }

    public string? DisplayName { get; init; }

    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}

public sealed record WolfAuthSubject
{
    public required WolfAuthSubjectId SubjectId { get; init; }

    public required WolfAuthProviderKey Provider { get; init; }

    public required WolfAuthExternalUserId ExternalUserId { get; init; }

    public string? DisplayName { get; init; }

    public string? Email { get; init; }

    public string? UserPrincipalName { get; init; }

    public IReadOnlyList<WolfAuthClaim> Claims { get; init; } = [];

    public IReadOnlyList<WolfAuthExternalGroup> Groups { get; init; } = [];
}
