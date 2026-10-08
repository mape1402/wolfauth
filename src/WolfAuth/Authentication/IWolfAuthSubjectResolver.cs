using System.Security.Claims;

namespace WolfAuth;

/// <summary>
/// Resolves normalized WolfAuth subjects from authenticated .NET principals.
/// </summary>
public interface IWolfAuthSubjectResolver
{
    /// <summary>
    /// Resolves a normalized WolfAuth subject from the provided claims principal.
    /// </summary>
    /// <param name="principal">The authenticated claims principal.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The subject resolution result.</returns>
    ValueTask<WolfAuthSubjectResolutionResult> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);
}
