namespace WolfAuth;

/// <summary>
/// Represents a subject persisted in a WolfAuth store.
/// </summary>
public sealed record WolfAuthStoredSubject
{
    /// <summary>
    /// Gets the normalized subject.
    /// </summary>
    public required WolfAuthSubject Subject { get; init; }

    /// <summary>
    /// Gets a value indicating whether the subject can receive authorization grants.
    /// </summary>
    public bool IsActive { get; init; } = true;

    /// <summary>
    /// Gets the timestamp when the subject was first stored.
    /// </summary>
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Gets the timestamp when the subject was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
}
