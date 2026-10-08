using System.Security.Claims;
using WolfAuth;
using WolfAuth.Microsoft.EntraId;

namespace WolfAuth.EntraIdWebSite;

/// <summary>
/// Provisions Microsoft Entra ID principals into WolfAuth during sign-in.
/// </summary>
internal sealed class EntraIdSignInProvisioner : IEntraIdSignInProvisioner
{
    private static readonly WolfAuthRoleKey SampleRoleKey = new("entra-web-user");
    private readonly IWolfAuthEntraIdProvisioningMapper _mapper;
    private readonly IWolfAuthProvisioningService _provisioningService;
    private readonly IWolfAuthAdministrationService _administrationService;

    /// <summary>
    /// Initializes a new instance of the <see cref="EntraIdSignInProvisioner"/> class.
    /// </summary>
    /// <param name="mapper">The Entra ID provisioning mapper.</param>
    /// <param name="provisioningService">The WolfAuth provisioning service.</param>
    /// <param name="administrationService">The WolfAuth administration service.</param>
    public EntraIdSignInProvisioner(
        IWolfAuthEntraIdProvisioningMapper mapper,
        IWolfAuthProvisioningService provisioningService,
        IWolfAuthAdministrationService administrationService)
    {
        _mapper = mapper;
        _provisioningService = provisioningService;
        _administrationService = administrationService;
    }

    /// <inheritdoc />
    public async Task ProvisionAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var mappedRequest = _mapper.CreateProvisioningRequest(principal);
        var request = mappedRequest with
        {
            SubjectId = new WolfAuthSubjectId(mappedRequest.ExternalUserId.ToString())
        };
        var result = await _provisioningService.UpsertSubjectAsync(request, cancellationToken);

        await _administrationService.UpsertAssignmentAsync(new WolfAuthAssignmentRequest
        {
            ActorSubjectId = result.Subject.SubjectId,
            Assignment = new WolfAuthAssignment
            {
                AssignmentId = $"sample-role:{result.Subject.SubjectId}",
                TargetKind = WolfAuthAssignmentTargetKind.Subject,
                SubjectId = result.Subject.SubjectId,
                GrantKind = WolfAuthAssignmentGrantKind.Role,
                RoleKey = SampleRoleKey,
                Source = "entra-id-sign-in"
            }
        }, cancellationToken);
    }
}
