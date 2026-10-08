namespace WolfAuth.Tests.Development;

/// <summary>
/// Tests the development subject factory.
/// </summary>
public sealed class WolfAuthDevelopmentSubjectFactoryTests
{
    /// <summary>
    /// Verifies that the factory creates a valid normalized subject for local development.
    /// </summary>
    [Fact]
    public void Create_ReturnsValidSubject_FromDevelopmentRequest()
    {
        IWolfAuthDevelopmentSubjectFactory factory = new WolfAuthDevelopmentSubjectFactory();
        var request = new WolfAuthDevelopmentSubjectRequest
        {
            ExternalUserId = "dev-user",
            Email = "dev@example.com",
            DisplayName = "Dev User",
            GroupIds = ["Developers", "Admins"],
            Claims =
            [
                new WolfAuthClaim
                {
                    Type = "mode",
                    Value = "development"
                }
            ]
        };

        var subject = factory.Create(request);

        Assert.Equal("dev-user", subject.SubjectId.ToString());
        Assert.Equal("dev-user", subject.ExternalUserId.ToString());
        Assert.Equal("development", subject.Provider.ToString());
        Assert.Equal("dev@example.com", subject.Email);
        Assert.Equal("Dev User", subject.DisplayName);
        Assert.Equal(2, subject.Groups.Count);
        Assert.Contains(subject.Groups, group => group.ExternalGroupId.ToString() == "Developers");
        Assert.Contains(subject.Claims, claim => claim.Type == "mode" && claim.Value == "development");
    }
}
