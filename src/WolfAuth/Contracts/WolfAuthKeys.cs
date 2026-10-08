namespace WolfAuth;

/// <summary>
/// Identifies a subject inside the host product authorization model.
/// </summary>
public readonly record struct WolfAuthSubjectId
{
    /// <summary>
    /// Creates a subject identifier.
    /// </summary>
    /// <param name="value">The subject identifier value.</param>
    public WolfAuthSubjectId(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the subject identifier value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the subject identifier value.
    /// </summary>
    /// <returns>The subject identifier value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into a subject identifier.
    /// </summary>
    /// <param name="value">The subject identifier value.</param>
    public static implicit operator WolfAuthSubjectId(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies the external identity provider that authenticated a subject.
/// </summary>
public readonly record struct WolfAuthProviderKey
{
    /// <summary>
    /// Creates an identity provider key.
    /// </summary>
    /// <param name="value">The provider key value.</param>
    public WolfAuthProviderKey(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the provider key value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the provider key value.
    /// </summary>
    /// <returns>The provider key value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into a provider key.
    /// </summary>
    /// <param name="value">The provider key value.</param>
    public static implicit operator WolfAuthProviderKey(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies a user inside an external identity provider.
/// </summary>
public readonly record struct WolfAuthExternalUserId
{
    /// <summary>
    /// Creates an external user identifier.
    /// </summary>
    /// <param name="value">The external user identifier value.</param>
    public WolfAuthExternalUserId(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the external user identifier value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the external user identifier value.
    /// </summary>
    /// <returns>The external user identifier value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into an external user identifier.
    /// </summary>
    /// <param name="value">The external user identifier value.</param>
    public static implicit operator WolfAuthExternalUserId(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies a group inside an external identity provider.
/// </summary>
public readonly record struct WolfAuthExternalGroupKey
{
    /// <summary>
    /// Creates an external group key.
    /// </summary>
    /// <param name="value">The external group key value.</param>
    public WolfAuthExternalGroupKey(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the external group key value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the external group key value.
    /// </summary>
    /// <returns>The external group key value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into an external group key.
    /// </summary>
    /// <param name="value">The external group key value.</param>
    public static implicit operator WolfAuthExternalGroupKey(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies an atomic permission defined by a host product.
/// </summary>
public readonly record struct WolfAuthPermissionKey
{
    /// <summary>
    /// Creates a permission key.
    /// </summary>
    /// <param name="value">The permission key value.</param>
    public WolfAuthPermissionKey(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the permission key value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the permission key value.
    /// </summary>
    /// <returns>The permission key value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into a permission key.
    /// </summary>
    /// <param name="value">The permission key value.</param>
    public static implicit operator WolfAuthPermissionKey(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies a host-defined role.
/// </summary>
public readonly record struct WolfAuthRoleKey
{
    /// <summary>
    /// Gets the conventional administrator role key.
    /// </summary>
    public static WolfAuthRoleKey Administrator { get; } = new("administrator");

    /// <summary>
    /// Creates a role key.
    /// </summary>
    /// <param name="value">The role key value.</param>
    public WolfAuthRoleKey(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the role key value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the role key value.
    /// </summary>
    /// <returns>The role key value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into a role key.
    /// </summary>
    /// <param name="value">The role key value.</param>
    public static implicit operator WolfAuthRoleKey(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies the scope where a permission or role grant applies.
/// </summary>
public readonly record struct WolfAuthScopeKey
{
    /// <summary>
    /// Gets the global scope key.
    /// </summary>
    public static WolfAuthScopeKey Global { get; } = new("global");

    /// <summary>
    /// Creates a scope key.
    /// </summary>
    /// <param name="value">The scope key value.</param>
    public WolfAuthScopeKey(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the scope key value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the scope key value.
    /// </summary>
    /// <returns>The scope key value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into a scope key.
    /// </summary>
    /// <param name="value">The scope key value.</param>
    public static implicit operator WolfAuthScopeKey(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}

/// <summary>
/// Identifies a host-defined authorization policy.
/// </summary>
public readonly record struct WolfAuthPolicyKey
{
    /// <summary>
    /// Creates a policy key.
    /// </summary>
    /// <param name="value">The policy key value.</param>
    public WolfAuthPolicyKey(string value) => Value = Require(value, nameof(value));

    /// <summary>
    /// Gets the policy key value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Returns the policy key value.
    /// </summary>
    /// <returns>The policy key value.</returns>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Converts a string value into a policy key.
    /// </summary>
    /// <param name="value">The policy key value.</param>
    public static implicit operator WolfAuthPolicyKey(string value) => new(value);

    private static string Require(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("WolfAuth keys cannot be empty.", parameterName);
        }

        return value.Trim();
    }
}
