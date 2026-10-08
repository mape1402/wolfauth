using System.Security.Claims;

namespace WolfAuth.Tests.Authentication;

/// <summary>
/// Tests edge cases for claims principal subject resolution.
/// </summary>
public sealed class WolfAuthClaimsPrincipalSubjectResolverEdgeTests
{
    /// <summary>
    /// Verifies that a null principal produces an invalid principal result.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsInvalidPrincipalResult_ForNullPrincipal()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();

        var result = await resolver.ResolveAsync(null!);

        Assert.False(result.Succeeded);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.InvalidPrincipal, result.FailureReason);
    }

    /// <summary>
    /// Verifies that missing provider values produce a stable failure result.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsMissingProvider_WhenDefaultProviderIsEmpty()
    {
        var options = new WolfAuthClaimsPrincipalMappingOptions
        {
            DefaultProvider = default,
            ProviderClaimType = "missing-provider"
        };
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver(options);
        var principal = Principal(new Claim("sub", "subject-1"));

        var result = await resolver.ResolveAsync(principal);

        Assert.False(result.Succeeded);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.MissingProvider, result.FailureReason);
    }

    /// <summary>
    /// Verifies that invalid mapped values produce invalid mapping results.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsInvalidMapping_WhenMappedValueIsInvalid()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();
        var principal = Principal(new Claim("sub", " "));

        var result = await resolver.ResolveAsync(principal);

        Assert.False(result.Succeeded);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.MissingExternalUserIdClaim, result.FailureReason);
    }

    /// <summary>
    /// Verifies that mapping failures inside subject materialization return invalid mapping results.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_ReturnsInvalidMapping_WhenClaimEnumerationFailsDuringMapping()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();
        var principal = new ThrowingClaimsPrincipal(
            [new Claim("sub", "subject-1")],
            throwAfterClaimEnumerationCount: 2);

        var result = await resolver.ResolveAsync(principal);

        Assert.False(result.Succeeded);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.InvalidMapping, result.FailureReason);
    }

    /// <summary>
    /// Verifies that duplicate and blank group claims are ignored.
    /// </summary>
    [Fact]
    public async Task ResolveAsync_IgnoresDuplicateAndBlankGroups()
    {
        var resolver = new WolfAuthClaimsPrincipalSubjectResolver();
        var principal = Principal(
            new Claim("sub", "subject-1"),
            new Claim("groups", "reviewers"),
            new Claim("groups", "reviewers"),
            new Claim("groups", " "));

        var result = await resolver.ResolveAsync(principal);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Subject);
        Assert.Single(result.Subject.Groups);
        Assert.Equal("reviewers", result.Subject.Groups[0].ExternalGroupId.ToString());
    }

    /// <summary>
    /// Creates an authenticated claims principal.
    /// </summary>
    /// <param name="claims">The principal claims.</param>
    /// <returns>The claims principal.</returns>
    private static ClaimsPrincipal Principal(params Claim[] claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    /// <summary>
    /// Provides a principal that fails after initial identity claim resolution.
    /// </summary>
    private sealed class ThrowingClaimsPrincipal : ClaimsPrincipal
    {
        private readonly IReadOnlyList<Claim> _claims;
        private readonly int _throwAfterClaimEnumerationCount;
        private int _claimEnumerationCount;

        /// <summary>
        /// Initializes a new instance of the <see cref="ThrowingClaimsPrincipal"/> class.
        /// </summary>
        /// <param name="claims">The claims returned before failure.</param>
        /// <param name="throwAfterClaimEnumerationCount">The number of successful claim enumerations.</param>
        public ThrowingClaimsPrincipal(
            IReadOnlyList<Claim> claims,
            int throwAfterClaimEnumerationCount)
            : base(new ClaimsIdentity(claims, "test"))
        {
            _claims = claims;
            _throwAfterClaimEnumerationCount = throwAfterClaimEnumerationCount;
        }

        /// <inheritdoc />
        public override IEnumerable<Claim> Claims
        {
            get
            {
                _claimEnumerationCount++;
                if (_claimEnumerationCount > _throwAfterClaimEnumerationCount)
                {
                    throw new ArgumentException("Claim enumeration failed.");
                }

                return _claims;
            }
        }
    }
}
