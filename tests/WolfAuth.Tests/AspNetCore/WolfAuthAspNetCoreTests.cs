using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using WolfAuth.AspNetCore;

namespace WolfAuth.Tests.AspNetCore;

/// <summary>
/// Tests ASP.NET Core integration.
/// </summary>
public sealed class WolfAuthAspNetCoreTests
{
    /// <summary>
    /// Verifies that WolfAuth policy names round-trip through the codec.
    /// </summary>
    [Fact]
    public void PolicyNameCodec_RoundTripsPermissionPolicyNames()
    {
        var codec = new WolfAuthPolicyNameCodec();

        var policyName = codec.CreatePermissionPolicyName(
            "contracts.events.view",
            "environment:qa");
        var parsed = codec.TryParse(policyName, out var parsedPolicyName);

        Assert.True(parsed);
        Assert.Equal(WolfAuthPolicyNameKind.Permission, parsedPolicyName.Kind);
        Assert.Equal("contracts.events.view", parsedPolicyName.PermissionKey?.ToString());
        Assert.Equal("environment:qa", parsedPolicyName.ScopeKey.ToString());
    }

    /// <summary>
    /// Verifies that the attribute emits a WolfAuth policy name.
    /// </summary>
    [Fact]
    public void PermissionAttribute_EmitsWolfAuthPolicyName()
    {
        var attribute = new WolfAuthPermissionAttribute("contracts.events.view", "tenant:one");

        Assert.StartsWith("WolfAuth:Permission:", attribute.Policy, StringComparison.Ordinal);
        Assert.Equal("contracts.events.view", attribute.PermissionKey);
        Assert.Equal("tenant:one", attribute.ScopeKey);
    }

    /// <summary>
    /// Verifies that ASP.NET Core authorization succeeds through WolfAuth handlers.
    /// </summary>
    [Fact]
    public async Task AuthorizationService_AllowsRegisteredPermission()
    {
        var subject = TestSubject("subject-1");
        var services = new ServiceCollection();
        services.AddWolfAuth(builder =>
        {
            builder.Registry.AddPermission("contracts.events.view");
            builder.Store = new WolfAuthInMemoryPersistenceStore(
                [new WolfAuthStoredSubject { Subject = subject }],
                [SubjectPermission("assignment-1", subject, "contracts.events.view")]);
        });
        using var serviceProvider = services.BuildServiceProvider();
        var principal = TestPrincipal("subject-1");
        serviceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
            User = principal
        };
        var authorizationService = serviceProvider.GetRequiredService<IAuthorizationService>();
        var policyName = serviceProvider
            .GetRequiredService<IWolfAuthPolicyNameCodec>()
            .CreatePermissionPolicyName("contracts.events.view");

        var result = await authorizationService.AuthorizeAsync(principal, null, policyName);

        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// Creates an authenticated test principal.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The authenticated principal.</returns>
    private static ClaimsPrincipal TestPrincipal(string subjectId)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", subjectId),
            new Claim(ClaimTypes.Name, "Test User")
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
            Provider = "default",
            ExternalUserId = subjectId
        };
    }

    /// <summary>
    /// Creates a direct permission assignment.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="subject">The target subject.</param>
    /// <param name="permissionKey">The permission key.</param>
    /// <returns>The assignment.</returns>
    private static WolfAuthAssignment SubjectPermission(
        string assignmentId,
        WolfAuthSubject subject,
        WolfAuthPermissionKey permissionKey)
    {
        return new WolfAuthAssignment
        {
            AssignmentId = assignmentId,
            TargetKind = WolfAuthAssignmentTargetKind.Subject,
            SubjectId = subject.SubjectId,
            GrantKind = WolfAuthAssignmentGrantKind.Permission,
            PermissionKey = permissionKey
        };
    }
}
