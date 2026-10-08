namespace WolfAuth;

/// <summary>
/// Represents an authorization context that can constrain a role or permission grant.
/// </summary>
public sealed record WolfAuthScope
{
    /// <summary>
    /// Gets the global scope that applies across all authorization contexts.
    /// </summary>
    public static WolfAuthScope Global { get; } = new()
    {
        Key = WolfAuthScopeKey.Global,
        Type = "global",
        DisplayName = "Global"
    };

    /// <summary>
    /// Gets the stable scope key.
    /// </summary>
    public required WolfAuthScopeKey Key { get; init; }

    /// <summary>
    /// Gets the scope type, such as environment, project, or space.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Gets the human-readable scope name.
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the scope description.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// Gets host-specific metadata associated with the scope.
    /// </summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}
