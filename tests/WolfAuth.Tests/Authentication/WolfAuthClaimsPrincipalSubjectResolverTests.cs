using System.Security.Claims;

namespace WolfAuth.Tests.Authentication;

/// <summary>
/// Tests the claims principal based WolfAuth subject resolver.
/// </summary>
public sealed class WolfAuthClaimsPrincipalSubjectResolverTests
{
    /// <summary>
    /// Verifies that anonymous principals produce an unauthenticated result.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsUnauthenticatedResult_ForAnonymousPrincipal()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        var result = await resolver.ResolveAsync(principal);

        Assert.False(result.Succeeded);
        Assert.Null(result.Subject);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.Unauthenticated, result.FailureReason);
    }

    /// <summary>
    /// Verifies that missing subject id claims produce a stable failure reason.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsMissingSubjectIdResult_WhenSubjectIdCannotBeResolved()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions
        {
            AllowSubjectIdFallbackToExternalUserId = false
        };
        options.SubjectIdClaimTypes.Clear();
        options.SubjectIdClaimTypes.Add("missing-subject-id");

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(new Claim("sub", "external-123"));

        var result = await resolver.ResolveAsync(principal);

        Assert.False(result.Succeeded);
        Assert.Null(result.Subject);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.MissingSubjectIdClaim, result.FailureReason);
    }

    /// <summary>
    /// Verifies that missing external user id claims produce a stable failure reason.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsMissingExternalUserIdResult_WhenExternalUserIdCannotBeResolved()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions();
        options.ExternalUserIdClaimTypes.Clear();
        options.ExternalUserIdClaimTypes.Add("missing-external-user-id");

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(new Claim("sub", "subject-123"));

        var result = await resolver.ResolveAsync(principal);

        Assert.False(result.Succeeded);
        Assert.Null(result.Subject);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.MissingExternalUserIdClaim, result.FailureReason);
    }

    /// <summary>
    /// Verifies that the external user id can be used as the subject id when fallback is enabled.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_UsesExternalUserIdAsSubjectId_WhenSubjectIdFallbackIsEnabled()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions();
        options.SubjectIdClaimTypes.Clear();
        options.SubjectIdClaimTypes.Add("missing-subject-id");

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(new Claim("sub", "external-123"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Equal("external-123", result.Subject.SubjectId.ToString());
        Assert.Equal("external-123", result.Subject.ExternalUserId.ToString());
    }

    /// <summary>
    /// Verifies that the configured default provider is used when no provider claim is configured.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_UsesDefaultProvider_WhenNoProviderClaimIsConfigured()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions
        {
            DefaultProvider = new WolfAuthProviderKey("local")
        };

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(new Claim("sub", "user-123"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Equal("local", result.Subject.Provider.ToString());
        Assert.Equal("user-123", result.Subject.SubjectId.ToString());
        Assert.Equal("user-123", result.Subject.ExternalUserId.ToString());
    }

    /// <summary>
    /// Verifies that a configured provider claim overrides the default provider.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_UsesProviderClaim_WhenConfiguredProviderClaimExists()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions
        {
            DefaultProvider = new WolfAuthProviderKey("default"),
            ProviderClaimType = "idp"
        };

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(
            new Claim("sub", "user-123"),
            new Claim("idp", "entra-id"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Equal("entra-id", result.Subject.Provider.ToString());
    }

    /// <summary>
    /// Verifies that display name, email, and UPN are mapped from configured claims.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_MapsProfileClaims_FromConfiguredClaimTypes()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();
        var principal = AuthenticatedPrincipal(
            new Claim("sub", "user-123"),
            new Claim("name", "Mario Perez"),
            new Claim("email", "mario@example.com"),
            new Claim("upn", "mario@example.com"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Equal("Mario Perez", result.Subject.DisplayName);
        Assert.Equal("mario@example.com", result.Subject.Email);
        Assert.Equal("mario@example.com", result.Subject.UserPrincipalName);
    }

    /// <summary>
    /// Verifies that configured group claims are mapped into external groups.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_MapsGroupClaims_ToExternalGroups()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();
        var principal = AuthenticatedPrincipal(
            new Claim("sub", "user-123"),
            new Claim("groups", "KnOwl-Admins"),
            new Claim("group", "KnOwl-Reviewers"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Equal(2, result.Subject.Groups.Count);
        Assert.Contains(result.Subject.Groups, group => group.ExternalGroupId.ToString() == "KnOwl-Admins");
        Assert.Contains(result.Subject.Groups, group => group.ExternalGroupId.ToString() == "KnOwl-Reviewers");
    }

    /// <summary>
    /// Verifies that claims are preserved when claim passthrough is enabled.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_PreservesClaims_WhenIncludeAllClaimsIsTrue()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions
        {
            IncludeAllClaims = true
        };

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(
            new Claim("sub", "user-123"),
            new Claim("custom", "value"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Contains(result.Subject.Claims, claim => claim.Type == "custom" && claim.Value == "value");
    }

    /// <summary>
    /// Verifies that claims are omitted when claim passthrough is disabled.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_OmitsClaims_WhenIncludeAllClaimsIsFalse()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions
        {
            IncludeAllClaims = false
        };

        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = AuthenticatedPrincipal(
            new Claim("sub", "user-123"),
            new Claim("custom", "value"));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Empty(result.Subject.Claims);
    }

    private static ClaimsPrincipal AuthenticatedPrincipal(params Claim[] claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }
}
