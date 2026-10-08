namespace WolfAuth;

public class WolfAuthRegistryException : InvalidOperationException
{
    public WolfAuthRegistryException(string message)
        : base(message)
    {
    }
}

public sealed class WolfAuthDuplicateRegistrationException : WolfAuthRegistryException
{
    public WolfAuthDuplicateRegistrationException(string kind, string key)
        : base($"A WolfAuth {kind} with key '{key}' has already been registered.")
    {
        Kind = kind;
        Key = key;
    }

    public string Kind { get; }

    public string Key { get; }
}
