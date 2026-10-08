using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using WolfAuth;
using WolfAuth.AspNetCore;

namespace WolfAuth.SampleApi;

/// <summary>
/// Starts the WolfAuth sample API.
/// </summary>
internal sealed class Program
{
    private const string SubjectId = "demo-user-1";
    private const string PermissionKey = "contracts.events.view";

    /// <summary>
    /// Configures and starts the sample API.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>A task that completes when the API shuts down.</returns>
    private static Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var subject = CreateSubject();
        var protectedPolicy = new WolfAuthPolicyNameCodec().CreatePermissionPolicyName(PermissionKey);

        builder.Services
            .AddAuthentication(DevelopmentAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, DevelopmentAuthenticationHandler>(
                DevelopmentAuthenticationHandler.SchemeName,
                _ => { });

        builder.Services.AddWolfAuth(wolf =>
        {
            wolf.Registry.AddPermission(
                PermissionKey,
                "View contract events",
                "Allows a user to inspect contract event history.",
                "Contracts",
                WolfAuthPermissionRiskLevel.Low);
            wolf.Registry.AddRole(
                "contract-reader",
                role => role.AddPermission(PermissionKey),
                "Contract Reader",
                "Can view contract event history.",
                isSystem: true);
            wolf.Store = new WolfAuthInMemoryPersistenceStore(
                [new WolfAuthStoredSubject { Subject = subject }],
                [
                    new WolfAuthAssignment
                    {
                        AssignmentId = "sample-contract-reader",
                        TargetKind = WolfAuthAssignmentTargetKind.Subject,
                        SubjectId = subject.SubjectId,
                        GrantKind = WolfAuthAssignmentGrantKind.Role,
                        RoleKey = "contract-reader"
                    }
                ]);
        });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseWolfAuth();
        app.UseAuthorization();

        app.MapGet("/contracts/{contractId}/events", (string contractId) =>
            Results.Ok(new
            {
                ContractId = contractId,
                Events = new[]
                {
                    new { Type = "created", Actor = SubjectId },
                    new { Type = "reviewed", Actor = SubjectId }
                }
            }))
            .RequireAuthorization(protectedPolicy);

        app.MapGet("/security/me", async (
            IWolfAuthCurrentSubjectAccessor subjectAccessor,
            IWolfAuthAdministrationService administrationService,
            CancellationToken cancellationToken) =>
        {
            var currentSubject = await subjectAccessor.GetCurrentSubjectAsync(cancellationToken);
            if (currentSubject is null)
            {
                return Results.Unauthorized();
            }

            var access = await administrationService.GetEffectiveAccessAsync(currentSubject, cancellationToken);
            return Results.Ok(access);
        });

        app.MapWolfAuthAdminApi("/security/wolfauth");

        return app.RunAsync();
    }

    /// <summary>
    /// Creates the sample subject seeded into the in-memory WolfAuth store.
    /// </summary>
    /// <returns>The seeded sample subject.</returns>
    private static WolfAuthSubject CreateSubject()
    {
        return new WolfAuthSubject
        {
            SubjectId = SubjectId,
            Provider = "sample-development",
            ExternalUserId = SubjectId,
            DisplayName = "Demo User",
            Email = "demo.user@example.com"
        };
    }
}

/// <summary>
/// Authenticates every sample request as the seeded development subject.
/// </summary>
internal sealed class DevelopmentAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    /// <summary>
    /// Identifies the development authentication scheme.
    /// </summary>
    public const string SchemeName = "Development";

    /// <summary>
    /// Initializes a new instance of the <see cref="DevelopmentAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The authentication options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public DevelopmentAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    /// <inheritdoc />
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("sub", "demo-user-1"),
            new Claim(ClaimTypes.Name, "Demo User"),
            new Claim(ClaimTypes.Email, "demo.user@example.com")
        ], SchemeName);
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
