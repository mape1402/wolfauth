namespace WolfAuth;

/// <summary>
/// Represents an error in WolfAuth registry configuration.
/// </summary>
public class WolfAuthRegistryException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthRegistryException"/> class.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public WolfAuthRegistryException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Represents a duplicate permission, role, or policy registration.
/// </summary>
public sealed class WolfAuthDuplicateRegistrationException : WolfAuthRegistryException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthDuplicateRegistrationException"/> class.
    /// </summary>
    /// <param name="kind">The duplicated registry item kind.</param>
    /// <param name="key">The duplicated registry item key.</param>
    public WolfAuthDuplicateRegistrationException(string kind, string key)
        : base($"A WolfAuth {kind} with key '{key}' has already been registered.")
    {
        Kind = kind;
        Key = key;
    }

    /// <summary>
    /// Gets the duplicated registry item kind.
    /// </summary>
    public string Kind { get; }

    /// <summary>
    /// Gets the duplicated registry item key.
    /// </summary>
    public string Key { get; }
}
