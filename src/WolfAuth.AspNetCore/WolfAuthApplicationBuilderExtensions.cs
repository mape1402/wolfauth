using Microsoft.AspNetCore.Builder;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Provides ASP.NET Core application builder helpers for WolfAuth.
/// </summary>
public static class WolfAuthApplicationBuilderExtensions
{
    /// <summary>
    /// Adds WolfAuth subject resolution middleware to the request pipeline.
    /// </summary>
    /// <param name="applicationBuilder">The application builder.</param>
    /// <returns>The application builder.</returns>
    public static IApplicationBuilder UseWolfAuth(this IApplicationBuilder applicationBuilder)
    {
        ArgumentNullException.ThrowIfNull(applicationBuilder);
        return applicationBuilder.UseMiddleware<WolfAuthMiddleware>();
    }
}
