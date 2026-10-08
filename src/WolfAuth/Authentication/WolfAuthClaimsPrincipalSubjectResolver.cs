using System.Security.Claims;

namespace WolfAuth;

/// <summary>
/// Resolves <see cref="WolfAuthSubject"/> instances from authenticated <see cref="ClaimsPrincipal"/> values.
/// </summary>
public sealed class WolfAuthClaimsPrincipalSubjectResolver : IWolfAuthSubjectResolver
{
    private readonly WolfAuthClaimsPrincipalMappingOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthClaimsPrincipalSubjectResolver"/> class.
    /// </summary>
    /// <param name="options">The claims principal mapping options.</param>
    public WolfAuthClaimsPrincipalSubjectResolver(WolfAuthClaimsPrincipalMappingOptions? options = null)
    {
        _options = options ?? new WolfAuthClaimsPrincipalMappingOptions();
    }

    /// <inheritdoc />
    public ValueTask<WolfAuthSubjectResolutionResult> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (principal is null)
        {
            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.InvalidPrincipal,
                "The claims principal cannot be null."));
        }

        if (!principal.Identities.Any(identity => identity.IsAuthenticated))
        {
            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.Unauthenticated,
                "The claims principal is not authenticated."));
        }

        var externalUserId = FirstClaimValue(principal, _options.ExternalUserIdClaimTypes);
        if (externalUserId is null)
        {
            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.MissingExternalUserIdClaim,
                "No external user id claim was found."));
        }

        var subjectId = FirstClaimValue(principal, _options.SubjectIdClaimTypes);
        if (subjectId is null && _options.AllowSubjectIdFallbackToExternalUserId)
        {
            subjectId = externalUserId;
        }

        if (subjectId is null)
        {
            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.MissingSubjectIdClaim,
                "No subject id claim was found."));
        }

        var providerValue = ResolveProviderValue(principal);
        if (providerValue is null)
        {
            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.MissingProvider,
                "No provider could be resolved."));
        }

        try
        {
            var provider = new WolfAuthProviderKey(providerValue);
            var subject = new WolfAuthSubject
            {
                SubjectId = new WolfAuthSubjectId(subjectId),
                Provider = provider,
                ExternalUserId = new WolfAuthExternalUserId(externalUserId),
                DisplayName = FirstClaimValue(principal, _options.DisplayNameClaimTypes),
                Email = FirstClaimValue(principal, _options.EmailClaimTypes),
                UserPrincipalName = FirstClaimValue(principal, _options.UserPrincipalNameClaimTypes),
                Claims = ResolveClaims(principal),
                Groups = ResolveGroups(principal, provider)
            };

            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Success(subject));
        }
        catch (ArgumentException exception)
        {
            return ValueTask.FromResult(WolfAuthSubjectResolutionResult.Failure(
                WolfAuthSubjectResolutionFailureReason.InvalidMapping,
                exception.Message));
        }
    }

    private string? ResolveProviderValue(ClaimsPrincipal principal)
    {
        if (!string.IsNullOrWhiteSpace(_options.ProviderClaimType))
        {
            var providerClaimValue = FirstClaimValue(principal, [_options.ProviderClaimType]);
            if (providerClaimValue is not null)
            {
                return providerClaimValue;
            }
        }

        var defaultProvider = _options.DefaultProvider.ToString();
        return string.IsNullOrWhiteSpace(defaultProvider) ? null : defaultProvider;
    }

    private IReadOnlyList<WolfAuthClaim> ResolveClaims(ClaimsPrincipal principal)
    {
        if (!_options.IncludeAllClaims)
        {
            return [];
        }

        return principal.Claims
            .Where(claim => !string.IsNullOrWhiteSpace(claim.Type))
            .Select(claim => new WolfAuthClaim
            {
                Type = claim.Type,
                Value = claim.Value,
                Issuer = string.IsNullOrWhiteSpace(claim.Issuer) ? null : claim.Issuer
            })
            .ToArray();
    }

    private IReadOnlyList<WolfAuthExternalGroup> ResolveGroups(
        ClaimsPrincipal principal,
        WolfAuthProviderKey provider)
    {
        var groups = new List<WolfAuthExternalGroup>();
        var seenGroupKeys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var claim in principal.Claims)
        {
            if (!_options.GroupClaimTypes.Contains(claim.Type, StringComparer.Ordinal) ||
                string.IsNullOrWhiteSpace(claim.Value) ||
                !seenGroupKeys.Add(claim.Value.Trim()))
            {
                continue;
            }

            groups.Add(new WolfAuthExternalGroup
            {
                Provider = provider,
                ExternalGroupId = new WolfAuthExternalGroupKey(claim.Value),
                Metadata = new Dictionary<string, string>
                {
                    ["claimType"] = claim.Type
                }
            });
        }

        return groups;
    }

    private static string? FirstClaimValue(ClaimsPrincipal principal, IEnumerable<string> claimTypes)
    {
        var candidateTypes = claimTypes
            .Where(claimType => !string.IsNullOrWhiteSpace(claimType))
            .ToArray();

        foreach (var claimType in candidateTypes)
        {
            var claim = principal.Claims.FirstOrDefault(candidate =>
                string.Equals(candidate.Type, claimType, StringComparison.Ordinal));

            if (!string.IsNullOrWhiteSpace(claim?.Value))
            {
                return claim.Value.Trim();
            }
        }

        return null;
    }
}
