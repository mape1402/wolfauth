using System.Net;
using System.Security.Claims;
using WolfAuth;

namespace WolfAuth.EntraIdWebSite;

/// <summary>
/// Renders the sample web site pages as small HTML documents.
/// </summary>
internal sealed class EntraIdPageRenderer : IEntraIdPageRenderer
{
    /// <inheritdoc />
    public string Home(ClaimsPrincipal principal)
    {
        var body = principal.Identity?.IsAuthenticated == true
            ? """
              <p>You are signed in with Microsoft Entra ID.</p>
              <p><a class="button" href="/dashboard">Open protected dashboard</a></p>
              <p><a href="/signout">Sign out</a></p>
              """
            : """
              <p>This sample asks Microsoft Entra ID to authenticate you before opening the protected dashboard.</p>
              <p><a class="button" href="/signin">Sign in with Entra ID</a></p>
              """;

        return Page("WolfAuth Entra ID Web Site", body);
    }

    /// <inheritdoc />
    public string Dashboard(
        ClaimsPrincipal principal,
        WolfAuthSubject subject,
        WolfAuthEffectiveAccess access)
    {
        var displayName = Encode(subject.DisplayName ?? principal.Identity?.Name ?? subject.SubjectId.ToString());
        var permissions = string.Join(
            string.Empty,
            access.Permissions.Select(permission =>
                $"<li>{Encode(permission.PermissionKey.ToString())} <small>{Encode(permission.Source.ToString())}</small></li>"));
        var claims = string.Join(
            string.Empty,
            principal.Claims
                .Take(12)
                .Select(claim => $"<li><strong>{Encode(claim.Type)}</strong>: {Encode(claim.Value)}</li>"));

        return Page(
            "Protected Dashboard",
            $"""
             <p>Welcome, <strong>{displayName}</strong>.</p>
             <p>Your Entra ID sign-in was mapped into WolfAuth subject <code>{Encode(subject.SubjectId.ToString())}</code>.</p>
             <h2>Effective Permissions</h2>
             <ul>{permissions}</ul>
             <h2>First Claims</h2>
             <ul>{claims}</ul>
             <p><a href="/">Home</a> | <a href="/signout">Sign out</a></p>
             """);
    }

    /// <summary>
    /// Wraps body content in the sample page shell.
    /// </summary>
    /// <param name="title">The page title.</param>
    /// <param name="body">The HTML body content.</param>
    /// <returns>The HTML document.</returns>
    private static string Page(string title, string body)
    {
        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>{{Encode(title)}}</title>
              <style>
                body { font-family: system-ui, sans-serif; margin: 3rem auto; max-width: 760px; line-height: 1.5; }
                .button { background: #0f6cbd; border-radius: .35rem; color: #fff; display: inline-block; padding: .75rem 1rem; text-decoration: none; }
                code { background: #f4f4f4; border-radius: .25rem; padding: .1rem .25rem; }
                small { color: #666; }
              </style>
            </head>
            <body>
              <h1>{{Encode(title)}}</h1>
              {{body}}
            </body>
            </html>
            """;
    }

    /// <summary>
    /// Encodes a value for HTML output.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The encoded value.</returns>
    private static string Encode(string value)
    {
        return WebUtility.HtmlEncode(value);
    }
}
