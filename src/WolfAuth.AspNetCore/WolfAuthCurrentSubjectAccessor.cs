using Microsoft.AspNetCore.Http;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Resolves and caches the current WolfAuth subject for an HTTP request.
/// </summary>
public sealed class WolfAuthCurrentSubjectAccessor : IWolfAuthCurrentSubjectAccessor
{
    private static readonly object SubjectItemKey = new();
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IWolfAuthSubjectResolver _subjectResolver;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthCurrentSubjectAccessor"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">The HTTP context accessor.</param>
    /// <param name="subjectResolver">The subject resolver.</param>
    public WolfAuthCurrentSubjectAccessor(
        IHttpContextAccessor httpContextAccessor,
        IWolfAuthSubjectResolver subjectResolver)
    {
        _httpContextAccessor = httpContextAccessor;
        _subjectResolver = subjectResolver;
    }

    /// <inheritdoc />
    public async ValueTask<WolfAuthSubject?> GetCurrentSubjectAsync(
        CancellationToken cancellationToken = default)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return null;
        }

        if (httpContext.Items.TryGetValue(SubjectItemKey, out var cachedSubject))
        {
            return cachedSubject as WolfAuthSubject;
        }

        var result = await _subjectResolver.ResolveAsync(httpContext.User, cancellationToken);
        if (!result.Succeeded || result.Subject is null)
        {
            return null;
        }

        httpContext.Items[SubjectItemKey] = result.Subject;
        return result.Subject;
    }
}
