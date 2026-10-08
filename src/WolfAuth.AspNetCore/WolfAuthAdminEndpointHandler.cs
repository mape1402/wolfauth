using Microsoft.AspNetCore.Http;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Handles WolfAuth administration endpoint requests.
/// </summary>
public sealed class WolfAuthAdminEndpointHandler : IWolfAuthAdminEndpointHandler
{
    private readonly IWolfAuthSubjectStore _subjectStore;
    private readonly IWolfAuthAssignmentValidator _assignmentValidator;
    private readonly IWolfAuthAdministrationService _administrationService;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthAdminEndpointHandler"/> class.
    /// </summary>
    /// <param name="subjectStore">The subject store.</param>
    /// <param name="assignmentValidator">The assignment validator.</param>
    /// <param name="administrationService">The administration service.</param>
    public WolfAuthAdminEndpointHandler(
        IWolfAuthSubjectStore subjectStore,
        IWolfAuthAssignmentValidator assignmentValidator,
        IWolfAuthAdministrationService administrationService)
    {
        _subjectStore = subjectStore;
        _assignmentValidator = assignmentValidator;
        _administrationService = administrationService;
    }

    /// <inheritdoc />
    public async Task<IResult> GetEffectiveAccessAsync(
        string subjectId,
        CancellationToken cancellationToken = default)
    {
        var storedSubject = await _subjectStore.FindSubjectAsync(
            new WolfAuthSubjectId(subjectId),
            cancellationToken);
        if (storedSubject is null)
        {
            return Results.NotFound();
        }

        var access = await _administrationService.GetEffectiveAccessAsync(
            storedSubject.Subject,
            cancellationToken);

        return Results.Ok(access);
    }

    /// <inheritdoc />
    public async Task<IResult> ValidateAssignmentAsync(
        WolfAuthAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        var validation = await _assignmentValidator.ValidateAsync(assignment, cancellationToken);
        return validation.IsValid ? Results.Ok(validation) : Results.BadRequest(validation);
    }

    /// <inheritdoc />
    public async Task<IResult> UpsertAssignmentAsync(
        WolfAuthAssignmentRequest request,
        CancellationToken cancellationToken = default)
    {
        var result = await _administrationService.UpsertAssignmentAsync(request, cancellationToken);
        return result.Succeeded ? Results.Ok(result) : Results.BadRequest(result);
    }

    /// <inheritdoc />
    public async Task<IResult> RemoveAssignmentAsync(
        string assignmentId,
        CancellationToken cancellationToken = default)
    {
        var removed = await _administrationService.RemoveAssignmentAsync(
            assignmentId,
            cancellationToken: cancellationToken);

        return removed ? Results.NoContent() : Results.NotFound();
    }
}
