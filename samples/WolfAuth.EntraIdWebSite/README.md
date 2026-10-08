# WolfAuth Entra ID Web Site Sample

This sample is a minimal web site that challenges the visitor with Microsoft Entra ID before opening a WolfAuth-protected dashboard.

## Entra ID App Registration

Create an app registration in Microsoft Entra ID with:

- Platform: Web
- Redirect URI: `https://localhost:7219/signin-oidc`
- Front-channel logout URL: `https://localhost:7219/signout-callback-oidc`
- ID tokens: enabled only if your tenant policy requires it; the sample uses authorization code flow.
- Client secret: create one for local testing.

## Local Configuration

Set local secrets:

```bash
dotnet user-secrets set "EntraId:TenantId" "<tenant-id>" --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj
dotnet user-secrets set "EntraId:ClientId" "<client-id>" --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj
dotnet user-secrets set "EntraId:ClientSecret" "<client-secret>" --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj
```

Run it:

```bash
dotnet run --project samples/WolfAuth.EntraIdWebSite/WolfAuth.EntraIdWebSite.csproj --urls "https://localhost:7219;http://localhost:5219"
```

Open `https://localhost:7219`, choose **Sign in with Entra ID**, and then open the protected dashboard.

On successful sign-in the sample:

- maps Entra ID claims into a WolfAuth provisioning request;
- stores the user in the in-memory WolfAuth store;
- assigns a sample `entra-web-user` role;
- protects `/dashboard` with a WolfAuth permission policy.
