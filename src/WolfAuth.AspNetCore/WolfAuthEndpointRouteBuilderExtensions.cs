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

        group.MapGet("/subjects/{subjectId}/effective-access", GetEffectiveAccessAsync)
            .WithName("WolfAuthGetEffectiveAccess");
        group.MapPost("/assignments/validate", ValidateAssignmentAsync)
            .WithName("WolfAuthValidateAssignment");
        group.MapPost("/assignments", UpsertAssignmentAsync)
            .WithName("WolfAuthUpsertAssignment");
        group.MapDelete("/assignments/{assignmentId}", RemoveAssignmentAsync)
            .WithName("WolfAuthRemoveAssignment");

        return group;
    }

    /// <summary>
    /// Handles effective access endpoint requests.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <param name="subjectStore">The subject store.</param>
    /// <param name="administrationService">The administration service.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    private static async Task<IResult> GetEffectiveAccessAsync(
        string subjectId,
        IWolfAuthSubjectStore subjectStore,
        IWolfAuthAdministrationService administrationService,
        CancellationToken cancellationToken)
    {
        var storedSubject = await subjectStore.FindSubjectAsync(
            new WolfAuthSubjectId(subjectId),
            cancellationToken);
        if (storedSubject is null)
        {
            return Results.NotFound();
        }

        var access = await administrationService.GetEffectiveAccessAsync(
            storedSubject.Subject,
            cancellationToken);

        return Results.Ok(access);
    }

    /// <summary>
    /// Handles assignment validation endpoint requests.
    /// </summary>
    /// <param name="assignment">The assignment to validate.</param>
    /// <param name="validator">The assignment validator.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    private static async Task<IResult> ValidateAssignmentAsync(
        WolfAuthAssignment assignment,
        IWolfAuthAssignmentValidator validator,
        CancellationToken cancellationToken)
    {
        var validation = await validator.ValidateAsync(assignment, cancellationToken);
        return validation.IsValid ? Results.Ok(validation) : Results.BadRequest(validation);
    }

    /// <summary>
    /// Handles assignment upsert endpoint requests.
    /// </summary>
    /// <param name="request">The assignment request.</param>
    /// <param name="administrationService">The administration service.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    private static async Task<IResult> UpsertAssignmentAsync(
        WolfAuthAssignmentRequest request,
        IWolfAuthAdministrationService administrationService,
        CancellationToken cancellationToken)
    {
        var result = await administrationService.UpsertAssignmentAsync(request, cancellationToken);
        return result.Succeeded ? Results.Ok(result) : Results.BadRequest(result);
    }

    /// <summary>
    /// Handles assignment removal endpoint requests.
    /// </summary>
    /// <param name="assignmentId">The assignment identifier.</param>
    /// <param name="administrationService">The administration service.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The endpoint result.</returns>
    private static async Task<IResult> RemoveAssignmentAsync(
        string assignmentId,
        IWolfAuthAdministrationService administrationService,
        CancellationToken cancellationToken)
    {
        var removed = await administrationService.RemoveAssignmentAsync(
            assignmentId,
            cancellationToken: cancellationToken);

        return removed ? Results.NoContent() : Results.NotFound();
    }
}
