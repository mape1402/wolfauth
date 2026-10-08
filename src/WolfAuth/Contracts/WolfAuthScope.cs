namespace WolfAuth;

public sealed record WolfAuthScope
{
    public static WolfAuthScope Global { get; } = new()
    {
        Key = WolfAuthScopeKey.Global,
        Type = "global",
        DisplayName = "Global"
    };

    public required WolfAuthScopeKey Key { get; init; }

    public required string Type { get; init; }

    public string? DisplayName { get; init; }

    public string? Description { get; init; }

    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}
