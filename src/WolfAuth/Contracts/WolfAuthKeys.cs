namespace WolfAuth;

internal static class WolfAuthKey
{
    public static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

public readonly record struct WolfAuthSubjectId
{
    public WolfAuthSubjectId(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthSubjectId(string value) => new(value);
}

public readonly record struct WolfAuthProviderKey
{
    public WolfAuthProviderKey(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthProviderKey(string value) => new(value);
}

public readonly record struct WolfAuthExternalUserId
{
    public WolfAuthExternalUserId(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthExternalUserId(string value) => new(value);
}

public readonly record struct WolfAuthExternalGroupKey
{
    public WolfAuthExternalGroupKey(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthExternalGroupKey(string value) => new(value);
}

public readonly record struct WolfAuthPermissionKey
{
    public WolfAuthPermissionKey(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthPermissionKey(string value) => new(value);
}

public readonly record struct WolfAuthRoleKey
{
    public static WolfAuthRoleKey Administrator { get; } = new("administrator");

    public WolfAuthRoleKey(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthRoleKey(string value) => new(value);
}

public readonly record struct WolfAuthScopeKey
{
    public static WolfAuthScopeKey Global { get; } = new("global");

    public WolfAuthScopeKey(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthScopeKey(string value) => new(value);
}

public readonly record struct WolfAuthPolicyKey
{
    public WolfAuthPolicyKey(string value) => Value = WolfAuthKey.Require(value, nameof(value));

    public string Value { get; }

    public override string ToString() => Value ?? string.Empty;

    public static implicit operator WolfAuthPolicyKey(string value) => new(value);
}
