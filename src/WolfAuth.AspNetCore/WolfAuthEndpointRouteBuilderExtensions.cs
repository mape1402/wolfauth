using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Provides minimal API endpoint helpers for WolfAuth administration.
/// </summary>
public static class WolfAuthEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps WolfAuth administration endpoints.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="prefix">The route prefix.</param>
    /// <returns>The created route group.</returns>
    public static RouteGroupBuilder MapWolfAuthAdminApi(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/wolfauth")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup(prefix);

        group.MapGet(
                "/subjects/{subjectId}/effective-access",
                (string subjectId, IWolfAuthAdminEndpointHandler handler, CancellationToken cancellationToken) =>
                    handler.GetEffectiveAccessAsync(subjectId, cancellationToken))
            .WithName("WolfAuthGetEffectiveAccess");
        group.MapPost(
                "/assignments/validate",
                (WolfAuthAssignment assignment, IWolfAuthAdminEndpointHandler handler, CancellationToken cancellationToken) =>
                    handler.ValidateAssignmentAsync(assignment, cancellationToken))
            .WithName("WolfAuthValidateAssignment");
        group.MapPost(
                "/assignments",
                (WolfAuthAssignmentRequest request, IWolfAuthAdminEndpointHandler handler, CancellationToken cancellationToken) =>
                    handler.UpsertAssignmentAsync(request, cancellationToken))
            .WithName("WolfAuthUpsertAssignment");
        group.MapDelete(
                "/assignments/{assignmentId}",
                (string assignmentId, IWolfAuthAdminEndpointHandler handler, CancellationToken cancellationToken) =>
                    handler.RemoveAssignmentAsync(assignmentId, cancellationToken))
            .WithName("WolfAuthRemoveAssignment");

        return group;
    }
}
