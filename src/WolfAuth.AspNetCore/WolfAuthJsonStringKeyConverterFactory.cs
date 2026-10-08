using System.Text.Json;
using System.Text.Json.Serialization;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Creates JSON converters that serialize WolfAuth key value objects as strings.
/// </summary>
internal sealed class WolfAuthJsonStringKeyConverterFactory : JsonConverterFactory
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(WolfAuthSubjectId) ||
            typeToConvert == typeof(WolfAuthProviderKey) ||
            typeToConvert == typeof(WolfAuthExternalUserId) ||
            typeToConvert == typeof(WolfAuthExternalGroupKey) ||
            typeToConvert == typeof(WolfAuthPermissionKey) ||
            typeToConvert == typeof(WolfAuthRoleKey) ||
            typeToConvert == typeof(WolfAuthScopeKey) ||
            typeToConvert == typeof(WolfAuthPolicyKey);
    }

    /// <inheritdoc />
    public override JsonConverter CreateConverter(
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (typeToConvert == typeof(WolfAuthSubjectId))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthSubjectId>(value => new WolfAuthSubjectId(value));
        }

        if (typeToConvert == typeof(WolfAuthProviderKey))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthProviderKey>(value => new WolfAuthProviderKey(value));
        }

        if (typeToConvert == typeof(WolfAuthExternalUserId))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthExternalUserId>(value => new WolfAuthExternalUserId(value));
        }

        if (typeToConvert == typeof(WolfAuthExternalGroupKey))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthExternalGroupKey>(value => new WolfAuthExternalGroupKey(value));
        }

        if (typeToConvert == typeof(WolfAuthPermissionKey))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthPermissionKey>(value => new WolfAuthPermissionKey(value));
        }

        if (typeToConvert == typeof(WolfAuthRoleKey))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthRoleKey>(value => new WolfAuthRoleKey(value));
        }

        if (typeToConvert == typeof(WolfAuthScopeKey))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthScopeKey>(value => new WolfAuthScopeKey(value));
        }

        if (typeToConvert == typeof(WolfAuthPolicyKey))
        {
            return new WolfAuthJsonStringKeyConverter<WolfAuthPolicyKey>(value => new WolfAuthPolicyKey(value));
        }

        throw new NotSupportedException($"The WolfAuth key type '{typeToConvert}' is not supported.");
    }
}

/// <summary>
/// Converts a WolfAuth key value object to and from a JSON string.
/// </summary>
/// <typeparam name="TValue">The WolfAuth key value type.</typeparam>
internal sealed class WolfAuthJsonStringKeyConverter<TValue> : JsonConverter<TValue>
    where TValue : struct
{
    private readonly Func<string, TValue> _factory;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthJsonStringKeyConverter{TValue}"/> class.
    /// </summary>
    /// <param name="factory">The factory used to create key values.</param>
    public WolfAuthJsonStringKeyConverter(Func<string, TValue> factory)
    {
        _factory = factory;
    }

    /// <inheritdoc />
    public override TValue Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a JSON string for WolfAuth key type '{typeToConvert}'.");
        }

        var value = reader.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new JsonException($"WolfAuth key type '{typeToConvert}' cannot be empty.");
        }

        return _factory(value);
    }

    /// <inheritdoc />
    public override void Write(
        Utf8JsonWriter writer,
        TValue value,
        JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}
