namespace WolfAuth;

/// <summary>
/// Creates normalized WolfAuth subjects for local development, tests, and demos.
/// </summary>
public sealed class WolfAuthDevelopmentSubjectFactory : IWolfAuthDevelopmentSubjectFactory
{
    /// <inheritdoc />
    public WolfAuthSubject Create(WolfAuthDevelopmentSubjectRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var subjectId = string.IsNullOrWhiteSpace(request.SubjectId)
            ? request.ExternalUserId
            : request.SubjectId;

        return new WolfAuthSubject
        {
            SubjectId = new WolfAuthSubjectId(subjectId),
            Provider = request.Provider,
            ExternalUserId = new WolfAuthExternalUserId(request.ExternalUserId),
            DisplayName = request.DisplayName,
            Email = request.Email,
            UserPrincipalName = request.UserPrincipalName,
            Claims = request.Claims,
            Groups = request.GroupIds
                .Where(groupId => !string.IsNullOrWhiteSpace(groupId))
                .Distinct(StringComparer.Ordinal)
                .Select(groupId => new WolfAuthExternalGroup
                {
                    Provider = request.Provider,
                    ExternalGroupId = new WolfAuthExternalGroupKey(groupId)
                })
                .ToArray()
        };
    }
}
