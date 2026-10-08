# WolfAuth Sample API

This sample hosts WolfAuth inside a minimal ASP.NET Core API. It seeds a development subject, grants the `contract-reader` role, protects a contract-events endpoint, exposes the current subject's effective access, and mounts the WolfAuth administration API under `/security/wolfauth`.

Run it with:

```bash
dotnet run --project samples/WolfAuth.SampleApi/WolfAuth.SampleApi.csproj
```

Useful endpoints:

- `GET /contracts/C-100/events`
- `GET /security/me`
- `GET /security/wolfauth/subjects/demo-user-1/effective-access`
