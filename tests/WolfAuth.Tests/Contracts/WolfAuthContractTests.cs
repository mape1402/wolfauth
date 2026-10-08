namespace WolfAuth.Tests.Contracts;

/// <summary>
/// Tests WolfAuth contract value objects and result helpers.
/// </summary>
public sealed class WolfAuthContractTests
{
    /// <summary>
    /// Verifies that key value objects trim values and expose implicit conversions.
    /// </summary>
    [Fact]
    public void Keys_TrimAndFormatValues()
    {
        Assert.Equal("subject", new WolfAuthSubjectId(" subject ").ToString());
        Assert.Equal("provider", new WolfAuthProviderKey(" provider ").ToString());
        Assert.Equal("external-user", new WolfAuthExternalUserId(" external-user ").ToString());
        Assert.Equal("external-group", new WolfAuthExternalGroupKey(" external-group ").ToString());
        Assert.Equal("permission", new WolfAuthPermissionKey(" permission ").ToString());
        Assert.Equal("role", new WolfAuthRoleKey(" role ").ToString());
        Assert.Equal("scope", new WolfAuthScopeKey(" scope ").ToString());
        Assert.Equal("policy", new WolfAuthPolicyKey(" policy ").ToString());

        WolfAuthPermissionKey permissionKey = "implicit.permission";
        Assert.Equal("implicit.permission", permissionKey.ToString());
    }

    /// <summary>
    /// Verifies that key value objects reject blank values.
    /// </summary>
    [Fact]
    public void Keys_RejectBlankValues()
    {
        Assert.Throws<ArgumentException>(() => new WolfAuthSubjectId(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthProviderKey(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthExternalUserId(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthExternalGroupKey(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthPermissionKey(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthRoleKey(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthScopeKey(" "));
        Assert.Throws<ArgumentException>(() => new WolfAuthPolicyKey(" "));
    }

    /// <summary>
    /// Verifies that default key values format as empty strings.
    /// </summary>
    [Fact]
    public void Keys_DefaultValuesFormatAsEmptyStrings()
    {
        Assert.Equal(string.Empty, default(WolfAuthSubjectId).ToString());
        Assert.Equal(string.Empty, default(WolfAuthProviderKey).ToString());
        Assert.Equal(string.Empty, default(WolfAuthExternalUserId).ToString());
        Assert.Equal(string.Empty, default(WolfAuthExternalGroupKey).ToString());
        Assert.Equal(string.Empty, default(WolfAuthPermissionKey).ToString());
        Assert.Equal(string.Empty, default(WolfAuthRoleKey).ToString());
        Assert.Equal(string.Empty, default(WolfAuthScopeKey).ToString());
        Assert.Equal(string.Empty, default(WolfAuthPolicyKey).ToString());
    }

    /// <summary>
    /// Verifies effective access permission checks across global, exact, and missing scopes.
    /// </summary>
    [Fact]
    public void EffectiveAccess_HasPermission_RespectsGlobalAndExactScopes()
    {
        var access = new WolfAuthEffectiveAccess
        {
            Subject = Subject("subject-1"),
            Permissions =
            [
                new WolfAuthPermissionGrant
                {
                    PermissionKey = "contracts.view",
                    ScopeKey = WolfAuthScopeKey.Global
                },
                new WolfAuthPermissionGrant
                {
                    PermissionKey = "contracts.edit",
                    ScopeKey = "environment:qa"
                }
            ]
        };

        Assert.True(access.HasPermission("contracts.view", "environment:prod"));
        Assert.True(access.HasPermission("contracts.edit", "environment:qa"));
        Assert.False(access.HasPermission("contracts.edit", "environment:prod"));
        Assert.False(access.HasPermission("contracts.delete"));
    }

    /// <summary>
    /// Verifies contract model properties that are mostly metadata carriers.
    /// </summary>
    [Fact]
    public void MetadataContracts_RoundTripValues()
    {
        var scope = new WolfAuthScope
        {
            Key = "environment:qa",
            Type = "environment",
            DisplayName = "QA",
            Description = "Quality assurance",
            Metadata = new Dictionary<string, string> { ["order"] = "2" }
        };
        var policy = new WolfAuthPolicy
        {
            Key = "contracts.promote",
            DisplayName = "Promote",
            Description = "Promotes a contract",
            RiskLevel = WolfAuthPermissionRiskLevel.High,
            RequiredPermissions = ["contracts.view"],
            Tags = ["workflow"]
        };
        var permission = new WolfAuthPermission
        {
            Key = "contracts.view",
            DisplayName = "View",
            Description = "Views contracts",
            Category = "Contracts",
            RiskLevel = WolfAuthPermissionRiskLevel.Low,
            Tags = ["read"]
        };

        Assert.Equal("global", WolfAuthScope.Global.Type);
        Assert.Equal("environment:qa", scope.Key.ToString());
        Assert.Equal("2", scope.Metadata["order"]);
        Assert.Equal("contracts.promote", policy.Key.ToString());
        Assert.Contains("workflow", policy.Tags);
        Assert.Equal("Contracts", permission.Category);
        Assert.Contains("read", permission.Tags);
    }

    /// <summary>
    /// Verifies evaluation result helper factories.
    /// </summary>
    [Fact]
    public void EvaluationResults_CreateAllowedAndDeniedResults()
    {
        var allowed = WolfAuthEvaluationResult.Allow(
            WolfAuthEvaluationReason.AllowedByRole,
            "environment:qa",
            "contracts.view",
            "contracts.policy",
            "reader");
        var denied = WolfAuthEvaluationResult.Deny(
            WolfAuthEvaluationReason.DeniedMissingPermission,
            "missing",
            "environment:qa",
            "contracts.delete",
            "contracts.policy");

        Assert.True(allowed.IsAllowed);
        Assert.Equal("reader", allowed.RoleKey?.ToString());
        Assert.False(denied.IsAllowed);
        Assert.Equal("missing", denied.Message);
        Assert.Equal("contracts.policy", denied.PolicyKey?.ToString());
    }

    /// <summary>
    /// Verifies subject resolution result helper factories.
    /// </summary>
    [Fact]
    public void SubjectResolutionResults_CreateSuccessAndFailureResults()
    {
        var subject = Subject("subject-1");
        var success = WolfAuthSubjectResolutionResult.Success(subject);
        var failure = WolfAuthSubjectResolutionResult.Failure(
            WolfAuthSubjectResolutionFailureReason.MissingProvider,
            "missing provider");

        Assert.True(success.Succeeded);
        Assert.Same(subject, success.Subject);
        Assert.False(failure.Succeeded);
        Assert.Equal(WolfAuthSubjectResolutionFailureReason.MissingProvider, failure.FailureReason);
        Assert.Equal("missing provider", failure.Message);
    }

    /// <summary>
    /// Creates a test subject.
    /// </summary>
    /// <param name="subjectId">The subject identifier.</param>
    /// <returns>The test subject.</returns>
    private static WolfAuthSubject Subject(string subjectId)
    {
        return new WolfAuthSubject
        {
            SubjectId = subjectId,
            Provider = "test",
            ExternalUserId = subjectId
        };
    }
}
