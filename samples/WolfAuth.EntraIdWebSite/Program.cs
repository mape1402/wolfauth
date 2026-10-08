using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using WolfAuth;
using WolfAuth.AspNetCore;
using WolfAuth.Microsoft.EntraId;

namespace WolfAuth.EntraIdWebSite;

/// <summary>
/// Starts the Microsoft Entra ID web site sample.
/// </summary>
internal sealed class Program
{
    /// <summary>
    /// Configures and starts the sample web site.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>A task that completes when the web site shuts down.</returns>
    private static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var sitePermission = new WolfAuthPermissionKey("site.dashboard.view");
        var siteRole = new WolfAuthRoleKey("entra-web-user");
        var dashboardPolicyName = new WolfAuthPolicyNameCodec().CreatePermissionPolicyName(sitePermission);

        builder.Services.Configure<EntraIdSampleOptions>(
            builder.Configuration.GetSection(EntraIdSampleOptions.SectionName));
        builder.Services.AddSingleton<IEntraIdPageRenderer, EntraIdPageRenderer>();
        builder.Services.AddScoped<IEntraIdSignInProvisioner, EntraIdSignInProvisioner>();
        builder.Services.AddSingleton<IWolfAuthEntraIdProvisioningMapper, WolfAuthEntraIdProvisioningMapper>();

        builder.Services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                var entraId = builder.Configuration
                    .GetSection(EntraIdSampleOptions.SectionName)
                    .Get<EntraIdSampleOptions>() ?? new EntraIdSampleOptions();

                options.Authority = $"https://login.microsoftonline.com/{entraId.TenantId}/v2.0";
                options.ClientId = entraId.ClientId;
                options.ClientSecret = entraId.ClientSecret;
                options.CallbackPath = entraId.CallbackPath;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.SaveTokens = true;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.TokenValidationParameters.NameClaimType = "name";
                options.TokenValidationParameters.RoleClaimType = "roles";
                options.Events.OnTokenValidated = async context =>
                {
                    if (context.Principal is null)
                    {
                        return;
                    }

                    var provisioner = context.HttpContext.RequestServices
                        .GetRequiredService<IEntraIdSignInProvisioner>();
                    await provisioner.ProvisionAsync(
                        context.Principal,
                        context.HttpContext.RequestAborted);
                };
            });

        builder.Services.AddWolfAuth(wolf =>
        {
            wolf.ClaimsMapping.DefaultProvider = "microsoft-entra-id";
            wolf.Registry.AddPermission(
                sitePermission,
                "View dashboard",
                "Allows the signed-in Entra ID user to view the sample dashboard.",
                "Sample",
                WolfAuthPermissionRiskLevel.Low);
            wolf.Registry.AddRole(
                siteRole,
                role => role.AddPermission(sitePermission),
                "Entra Web User",
                "Default role assigned by this Entra ID web site sample.",
                isSystem: true);
        });

        var app = builder.Build();
        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseWolfAuth();

        app.MapGet("/", (HttpContext context, IEntraIdPageRenderer renderer) =>
                Results.Content(renderer.Home(context.User), "text/html"))
            .AllowAnonymous();

        app.MapGet("/signin", () =>
                Results.Challenge(
                    new AuthenticationProperties { RedirectUri = "/dashboard" },
                    [OpenIdConnectDefaults.AuthenticationScheme]))
            .AllowAnonymous();

        app.MapGet("/signout", () =>
            Results.SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

        app.MapGet("/dashboard", async (
                HttpContext context,
                IWolfAuthCurrentSubjectAccessor subjectAccessor,
                IWolfAuthAdministrationService administrationService,
                IEntraIdPageRenderer renderer,
                CancellationToken cancellationToken) =>
            {
                var subject = await subjectAccessor.GetCurrentSubjectAsync(cancellationToken);
                if (subject is null)
                {
                    return Results.Challenge();
                }

                var access = await administrationService.GetEffectiveAccessAsync(subject, cancellationToken);
                return Results.Content(renderer.Dashboard(context.User, subject, access), "text/html");
            })
            .RequireAuthorization(dashboardPolicyName);

        app.MapWolfAuthAdminApi("/wolfauth");

        await app.RunAsync();
    }
}
