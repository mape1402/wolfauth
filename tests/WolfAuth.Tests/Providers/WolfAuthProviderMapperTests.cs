using System.Security.Claims;
using WolfAuth.Microsoft.EntraId;
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
    /// Verifies that the OpenID Connect mapper throws when the required user id is absent.
    /// </summary>
    [Fact]
    public void OpenIdConnectMapper_ThrowsWhenRequiredClaimIsMissing()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Email, "user@example.com")
        ], "oidc"));
        var mapper = new WolfAuthOpenIdConnectProvisioningMapper();

        Assert.Throws<InvalidOperationException>(() => mapper.CreateProvisioningRequest(principal));
    }

    /// <summary>
    /// Verifies that OpenID Connect options can customize provider and group claim mapping.
    /// </summary>
    [Fact]
    public void OpenIdConnectMapper_UsesCustomOptions()
    {
        var options = new WolfAuthOpenIdConnectMappingOptions
        {
            Provider = "custom-oidc",
            ExternalUserIdClaimType = "uid",
            DisplayNameClaimType = "display",
            EmailClaimType = "mail",
            UserPrincipalNameClaimType = "upn"
        };
        options.GroupClaimTypes.Clear();
        options.GroupClaimTypes.Add("roles");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("uid", "user-1"),
            new Claim("display", "User One"),
            new Claim("mail", "user@example.com"),
            new Claim("upn", "user@example.com"),
            new Claim("roles", "operators")
        ], "oidc"));
        var mapper = new WolfAuthOpenIdConnectProvisioningMapper(options);

        var request = mapper.CreateProvisioningRequest(principal);

        Assert.Equal("custom-oidc", request.Provider.ToString());
        Assert.Equal("User One", request.DisplayName);
        Assert.Equal("user@example.com", request.Email);
        Assert.Equal("user@example.com", request.UserPrincipalName);
        Assert.Contains(request.Groups, group => group.ExternalGroupId.ToString() == "operators");
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

    /// <summary>
    /// Verifies that the Entra ID mapper uses the fallback user identifier when object id is absent.
    /// </summary>
    [Fact]
    public void EntraIdMapper_UsesFallbackUserIdWhenObjectIdIsMissing()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "fallback-1")
        ], "entra"));
        var mapper = new WolfAuthEntraIdProvisioningMapper();

        var request = mapper.CreateProvisioningRequest(principal);

        Assert.Equal("fallback-1", request.ExternalUserId.ToString());
    }

    /// <summary>
    /// Verifies that the Entra ID mapper uses custom claim mapping options.
    /// </summary>
    [Fact]
    public void EntraIdMapper_UsesCustomOptions()
    {
        var options = new WolfAuthEntraIdMappingOptions
        {
            Provider = "entra-test",
            ObjectIdClaimType = "object_id",
            FallbackUserIdClaimType = "fallback_id",
            DisplayNameClaimType = "display",
            EmailClaimType = "mail",
            UserPrincipalNameClaimType = "upn"
        };
        options.GroupClaimTypes.Clear();
        options.GroupClaimTypes.Add("roles");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("object_id", "object-1"),
            new Claim("fallback_id", "fallback-1"),
            new Claim("display", "User One"),
            new Claim("mail", "user@example.com"),
            new Claim("upn", "user@example.com"),
            new Claim("roles", "approvers")
        ], "entra"));
        var mapper = new WolfAuthEntraIdProvisioningMapper(options);

        var request = mapper.CreateProvisioningRequest(principal);

        Assert.Equal("entra-test", request.Provider.ToString());
        Assert.Equal("object-1", request.ExternalUserId.ToString());
        Assert.Equal("User One", request.DisplayName);
        Assert.Equal("user@example.com", request.Email);
        Assert.Equal("user@example.com", request.UserPrincipalName);
        Assert.Contains(request.Groups, group => group.ExternalGroupId.ToString() == "approvers");
    }

    /// <summary>
    /// Verifies that the Entra ID mapper throws when neither object id nor fallback id exists.
    /// </summary>
    [Fact]
    public void EntraIdMapper_ThrowsWhenNoUserIdExists()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("name", "User")
        ], "entra"));
        var mapper = new WolfAuthEntraIdProvisioningMapper();

        Assert.Throws<InvalidOperationException>(() => mapper.CreateProvisioningRequest(principal));
    }
}
