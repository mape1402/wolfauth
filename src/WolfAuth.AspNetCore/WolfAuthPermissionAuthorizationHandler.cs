using Microsoft.AspNetCore.Authorization;

namespace WolfAuth.AspNetCore;

/// <summary>
/// Handles ASP.NET Core authorization checks for WolfAuth permissions.
/// </summary>
public sealed class WolfAuthPermissionAuthorizationHandler :
    AuthorizationHandler<WolfAuthPermissionRequirement>
{
    private readonly IWolfAuthCurrentSubjectAccessor _subjectAccessor;
    private readonly IWolfAuthEvaluator _evaluator;

    /// <summary>
    /// Initializes a new instance of the <see cref="WolfAuthPermissionAuthorizationHandler"/> class.
    /// </summary>
    /// <param name="subjectAccessor">The current subject accessor.</param>
    /// <param name="evaluator">The WolfAuth evaluator.</param>
    public WolfAuthPermissionAuthorizationHandler(
        IWolfAuthCurrentSubjectAccessor subjectAccessor,
        IWolfAuthEvaluator evaluator)
    {
        _subjectAccessor = subjectAccessor;
        _evaluator = evaluator;
    }

    /// <inheritdoc />
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        WolfAuthPermissionRequirement requirement)
    {
        var subject = await _subjectAccessor.GetCurrentSubjectAsync();
        if (subject is null)
        {
            return;
        }

        var result = await _evaluator.CanAsync(WolfAuthEvaluationContext.ForPermission(
            subject,
            requirement.PermissionKey,
            requirement.ScopeKey,
            context.Resource));

        if (result.IsAllowed)
        {
            context.Succeed(requirement);
        }
    }
}
