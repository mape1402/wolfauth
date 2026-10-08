using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WolfAuth.AspNetCore;
using HttpJsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

namespace WolfAuth.Tests.Integration;

/// <summary>
/// Tests WolfAuth behavior through an ASP.NET Core host.
/// </summary>
public sealed class WolfAuthAspNetCoreIntegrationTests
{
    /// <summary>
    /// Verifies a protected endpoint allows subjects with matching assignments.
    /// </summary>
    [Fact]
    public async Task ProtectedEndpoint_AllowsSubjectWithPermissionAssignment()
    {
        using var server = CreateServer(grantProtectedPermission: true);
        using var client = server.CreateClient();

        var response = await client.GetAsync("/contracts");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>
    /// Verifies a protected endpoint denies subjects without matching assignments.
    /// </summary>
    [Fact]
    public async Task ProtectedEndpoint_DeniesSubjectWithoutPermissionAssignment()
    {
        using var server = CreateServer(grantProtectedPermission: false);
        using var client = server.CreateClient();

        var response = await client.GetAsync("/contracts");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>
    /// Verifies the administration API handles effective access, validation, upsert, and removal.
    /// </summary>
    [Fact]
    public async Task AdminApi_HandlesEffectiveAccessValidationUpsertAndRemoval()
    {
        using var server = CreateServer(grantProtectedPermission: false);
        using var client = server.CreateClient();
        var jsonOptions = server.Services
            .GetRequiredService<IOptions<HttpJsonOptions>>()
            .Value
            .SerializerOptions;
        var assignment = SubjectPermission("assignment-1", "subject-1", "contracts.events.view");

        var effectiveAccess = await client.GetAsync("/security/subjects/subject-1/effective-access");
        var validation = await client.PostAsJsonAsync("/security/assignments/validate", assignment, jsonOptions);
        var upsert = await client.PostAsJsonAsync("/security/assignments", new WolfAuthAssignmentRequest
        {
            ActorSubjectId = "admin-1",
            Assignment = assignment
        }, jsonOptions);
        var removal = await client.DeleteAsync("/security/assignments/assignment-1");

        Assert.Equal(HttpStatusCode.OK, effectiveAccess.StatusCode);
        Assert.Equal(HttpStatusCode.OK, validation.StatusCode);
        Assert.Equal(HttpStatusCode.OK, upsert.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, removal.StatusCode);
    }

    /// <summary>
    /// Creates a test server hosting WolfAuth endpoints.
    /// </summary>
    /// <param name="grantProtectedPermission">Whether to seed the protected endpoint permission.</param>
    /// <returns>The configured test server.</returns>
    private static TestServer CreateServer(bool grantProtectedPermission)
    {
        var subject = TestSubject("subject-1");
        IReadOnlyList<WolfAuthAssignment> assignments = grantProtectedPermission
            ? [SubjectPermission("protected-permission", subject.SubjectId, "contracts.events.view")]
            : Array.Empty<WolfAuthAssignment>();
        var policyName = new WolfAuthPolicyNameCodec()
            .CreatePermissionPolicyName("contracts.events.view");

        var builder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services
                    .AddAuthentication("Test")
                    .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>("Test", _ => { });
                services.AddWolfAuth(wolf =>
                {
                    wolf.Registry.AddPermission("contracts.events.view");
                    wolf.Registry.AddRole("reader", role => role.AddPermission("contracts.events.view"));
                    wolf.Store = new WolfAuthInMemoryPersistenceStore(
                        [new WolfAuthStoredSubject { Subject = subject }],
                        assignments);
                });
            })
            .Configure(application =>
            {
                application.UseRouting();
                application.UseAuthentication();
                application.UseAuthorization();
                application.UseEndpoints(endpoints =>
                {
                    endpoints
                        .MapGet("/contracts", () => Results.Ok(new { message = "allowed" }))
                        .RequireAuthorization(policyName);
                    endpoints.MapWolfAuthAdminApi("/security");
                });
            });

        return new TestServer(builder);
    }

    /// <summary>
    /// Creates a subject permission assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="permissionKey">The permission key.</param>
    /// <returns>The assignment.</returns>
    private static WolfAuthAssignment SubjectPermission(
        string assignmentId,
        WolfAuthSubjectId subjectId,
        WolfAuthPermissionKey permissionKey)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = permissionKey
        };
    }

    /// <summary>
    /// Creates an authenticated test principal.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The authenticated test principal.</returns>
    private static ClaimsPrincipal TestPrincipal(string subjectId)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", subjectId)
        ], "test"));
    }

    /// <summary>
    /// Creates a test subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The test subject.</returns>
    private static WolfAuthSubject TestSubject(string subjectId)
    {
        return new WolfAuthSubject
        {
            SubjectId = subjectId,
            Provider = "test",
            ExternalUserId = subjectId,
            DisplayName = "Test Subject"
        };
    }

    /// <summary>
    /// Authenticates every integration-test request as the seeded subject.
    /// </summary>
    private sealed class TestAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TestAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="options">The authentication scheme options.</param>
        /// <param name="logger">The logger factory.</param>
        /// <param name="encoder">The URL encoder.</param>
        public TestAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        /// <inheritdoc />
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var ticket = new AuthenticationTicket(
                TestPrincipal("subject-1"),
                Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
