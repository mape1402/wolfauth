using Microsoft.AspNetCore.Http;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Resolves the current WolfAuth subject early in the ASP.NET Core request pipeline.
/// </summary>
public sealed class WolfAuthMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next request delegate.</param>
    public WolfAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Invokes the middleware.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="subjectAccessor">The current subject accessor.</param>
    /// <returns>A task that completes when the request has been processed.</returns>
    public async Task InvokeAsync(
        HttpContext context,
        IWolfAuthCurrentSubjectAccessor subjectAccessor)
    {
        await subjectAccessor.GetCurrentSubjectAsync(context.RequestAborted);
        await _next(context);
    }
}
