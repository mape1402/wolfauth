<p align="center">
  <img src="assets/wolfauth-logo.png" alt="WolfAuth" width="360" />
</p>

<p align="center">
  <a href="https://github.com/mape1402/wolfauth/actions/workflows/build-and-release.yml">
    <img src="https://github.com/mape1402/wolfauth/actions/workflows/build-and-release.yml/badge.svg?branch=main" alt="Build" />
  </a>
  <a href="https://www.nuget.org/packages/WolfAuth">
    <img src="https://img.shields.io/nuget/v/WolfAuth.svg?label=package" alt="Package" />
  </a>
  <a href="https://www.nuget.org/packages/WolfAuth">
    <img src="https://img.shields.io/nuget/dt/WolfAuth.svg?label=downloads" alt="Downloads" />
  </a>
  <a href="https://github.com/mape1402/wolfauth/actions/workflows/build-and-release.yml">
    <img src="https://img.shields.io/badge/coverage-100%25-brightgreen.svg" alt="Coverage" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/mape1402/wolfauth.svg" alt="License" />
  </a>
</p>

# WolfAuth

WolfAuth is a .NET authentication foundation for products that need a consistent way to normalize signed-in users across identity providers.

The v1 technical cut is intentionally focused on **Authentication**. It provides the stable path for mapping an authenticated `ClaimsPrincipal` into a WolfAuth subject, integrating that subject with ASP.NET Core, and using Microsoft Entra ID through OpenID Connect. Authorization and persistence building blocks exist in the repository, but they are not the v1 stable surface.

## Stable In v1

- ASP.NET Core service registration and request pipeline integration.
- Current-subject resolution from `ClaimsPrincipal`.
- OpenID Connect claims mapping.
- Microsoft Entra ID subject and group mapping.
- Optional in-memory provisioning for samples and local validation.
- XML documentation files generated for packaged assemblies.
- NuGet package metadata, README, icon, repository links, symbols, and source package support.

## Packages

Install the packages you need for the authentication path:

```bash
dotnet add package WolfAuth
dotnet add package WolfAuth.AspNetCore
dotnet add package WolfAuth.OpenIdConnect
dotnet add package WolfAuth.Microsoft.EntraId
```

Package roles:

- `WolfAuth`: core contracts, subject model, claims-based subject resolution, and in-memory support.
- `WolfAuth.AspNetCore`: ASP.NET Core registration, current subject access, and middleware.
- `WolfAuth.OpenIdConnect`: generic OpenID Connect provisioning mapper.
- `WolfAuth.Microsoft.EntraId`: Microsoft Entra ID mapper built on the OpenID Connect model.

`WolfAuth.EntityFrameworkCore` is kept as an internal work-in-progress package for the future storage/authorization track and is not part of the v1 publishable package set.

## Getting Started With ASP.NET Core And Entra ID

Register your normal ASP.NET Core authentication handlers, then add WolfAuth and the Entra ID mapper:

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using WolfAuth.AspNetCore;
using WolfAuth.Microsoft.EntraId;

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;
        options.CallbackPath = "/signin-oidc";
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.SaveTokens = true;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
    });

builder.Services.AddSingleton<IWolfAuthEntraIdProvisioningMapper, WolfAuthEntraIdProvisioningMapper>();

builder.Services.AddWolfAuth(wolf =>
{
    wolf.ClaimsMapping.DefaultProvider = "microsoft-entra-id";
});
```

Use WolfAuth after ASP.NET Core authentication and before authorization:

```csharp
app.UseAuthentication();
app.UseWolfAuth();
app.UseAuthorization();
```

Resolve the current WolfAuth subject anywhere in a scoped service or endpoint:

```csharp
app.MapGet("/me", async (
    IWolfAuthCurrentSubjectAccessor subjectAccessor,
    CancellationToken cancellationToken) =>
{
    var subject = await subjectAccessor.GetCurrentSubjectAsync(cancellationToken);
    return subject is null ? Results.Unauthorized() : Results.Ok(subject);
});
```

For pure authentication binding, no database storage is required. WolfAuth can resolve the current subject directly from the authenticated principal. Storage becomes relevant when your application starts persisting subjects, assignments, audit entries, or future authorization data.

## Optional Sign-In Provisioning

If you want to persist a signed-in Entra ID user during token validation, map the principal into a provisioning request:

```csharp
options.Events.OnTokenValidated = async context =>
{
    if (context.Principal is null)
    {
        return;
    }

    var mapper = context.HttpContext.RequestServices
        .GetRequiredService<IWolfAuthEntraIdProvisioningMapper>();
    var provisioning = context.HttpContext.RequestServices
        .GetRequiredService<IWolfAuthProvisioningService>();

    var request = mapper.CreateProvisioningRequest(context.Principal);
    await provisioning.UpsertSubjectAsync(request, context.HttpContext.RequestAborted);
};
```

The default registration uses the in-memory WolfAuth store. It is useful for local samples and early integration tests, but production persistence is outside the v1 authentication cut.

## Run The Entra ID Web Site Sample

Create an app registration in Microsoft Entra ID:

- Platform: Web.
- Redirect URI: `https://localhost:7219/signin-oidc`.
- Front-channel logout URL: `https://localhost:7219/signout-callback-oidc`.
- Authorization code flow with PKCE. A client secret is optional and only needed when you want the host to run as a confidential client.

Store local secrets:

```bash
dotnet user-secrets set "EntraId:TenantId" "<tenant-id>" --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj
dotnet user-secrets set "EntraId:ClientId" "<client-id>" --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj
```

Run the sample:

```bash
dotnet run --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj --urls "https://localhost:7219;http://localhost:5219"
```

Open `https://localhost:7219`, choose **Sign in with Entra ID**, and then open the protected dashboard.

## Build, Test, And Pack Locally

```bash
dotnet restore WolfAuth.sln
dotnet build WolfAuth.sln --configuration Release /warnaserror:CS1591
dotnet test tests/WolfAuth.Tests/WolfAuth.Tests.csproj --configuration Release
dotnet pack src/WolfAuth/WolfAuth.csproj --configuration Release --output ./nupkgs
dotnet pack src/WolfAuth.AspNetCore/WolfAuth.AspNetCore.csproj --configuration Release --output ./nupkgs
dotnet pack src/WolfAuth.OpenIdConnect/WolfAuth.OpenIdConnect.csproj --configuration Release --output ./nupkgs
dotnet pack src/WolfAuth.Microsoft.EntraId/WolfAuth.Microsoft.EntraId.csproj --configuration Release --output ./nupkgs
```

The packages include XML documentation, symbols, source, the package README, and `wolfauth-icon.png` as the NuGet icon.

## Release Notes

See [CHANGELOG.md](CHANGELOG.md) for the v1 authentication cut and future changes.
