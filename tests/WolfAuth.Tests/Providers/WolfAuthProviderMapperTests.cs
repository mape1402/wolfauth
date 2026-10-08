using System.Security.Claims;
using WolfAuth.MicrosoftEntraId;
using WolfAuth.OpenIdConnect;

namespace WolfAuth.Tests.Providers;

/// <summary>
/// Tests provider provisioning mappers.
/// </summary>
public sealed class WolfAuthProviderMapperTests
{
    /// <summary>
    /// Verifies that the OpenID Connect mapper creates provisioning requests.
    /// </summary>
    [Fact]
    public void OpenIdConnectMapper_CreatesProvisioningRequest()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "user-1"),
            new Claim(ClaimTypes.Email, "user@example.com"),
            new Claim("groups", "reviewers")
        ], "oidc"));
        var mapper = new WolfAuthOpenIdConnectProvisioningMapper();

        var request = mapper.CreateProvisioningRequest(principal);

        Assert.Equal("oidc", request.Provider.ToString());
        Assert.Equal("user-1", request.ExternalUserId.ToString());
        Assert.Equal("user@example.com", request.Email);
        Assert.Contains(request.Groups, group => group.ExternalGroupId.ToString() == "reviewers");
    }

    /// <summary>
    /// Verifies that the Microsoft Entra ID mapper prefers the object identifier.
    /// </summary>
    [Fact]
    public void EntraIdMapper_UsesObjectIdAndGroups()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("oid", "object-1"),
            new Claim("preferred_username", "user@example.com"),
            new Claim("groups", "group-1")
        ], "entra"));
        var mapper = new WolfAuthEntraIdProvisioningMapper();

        var request = mapper.CreateProvisioningRequest(principal);

        Assert.Equal("microsoft-entra-id", request.Provider.ToString());
        Assert.Equal("object-1", request.ExternalUserId.ToString());
        Assert.Equal("user@example.com", request.UserPrincipalName);
        Assert.Contains(request.Groups, group => group.ExternalGroupId.ToString() == "group-1");
    }
}
