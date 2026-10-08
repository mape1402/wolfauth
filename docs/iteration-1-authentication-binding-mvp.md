# Iteration 1: Authentication Binding MVP

Date: 2026-10-07

## Objective

Implement the first WolfAuth authentication binding layer.

Iteration 0 defined the normalized identity contract through `WolfAuthSubject`, claims, external groups, provider keys, and external user identifiers. Iteration 1 should make that contract usable by mapping an already-authenticated .NET identity into a `WolfAuthSubject`.

WolfAuth should not become an identity provider in this iteration. The host still owns the actual login challenge, cookie, bearer token, OpenID Connect, or local development authentication setup. WolfAuth owns the normalized subject binding that authorization can consume consistently.

## Outcome

At the end of this iteration, a host should be able to:

- Take an authenticated `ClaimsPrincipal`.
- Resolve a normalized `WolfAuthSubject`.
- Configure which claims map to subject id, provider, external user id, display name, email, UPN, and groups.
- Preserve useful claims for later policies.
- Resolve external groups from one or more claim types.
- Use a local/development subject factory for tests and early host wiring.
- Run unit tests that prove subject resolution behavior.

## Guiding Principles

- Authentication proves identity; authorization still decides access.
- The binding layer consumes authenticated identities; it does not implement provider login flows.
- Keep the first binding framework-light by depending on `System.Security.Claims`, not ASP.NET Core.
- Keep provider-specific adapters out of this iteration.
- Make claim mapping explicit and testable.
- Preserve the existing XML documentation standard for all public APIs.

## In Scope

- `ClaimsPrincipal` to `WolfAuthSubject` mapping.
- Subject resolution result type for success, unauthenticated, and invalid mapping outcomes.
- Claim mapping options.
- Default claim type conventions for common .NET/OIDC claims.
- Group claim extraction.
- Provider key resolution from options or claims.
- External user id resolution from claims.
- Display name, email, and UPN resolution from claims.
- Claim passthrough into `WolfAuthSubject.Claims`.
- Local/development subject factory for tests and demos.
- Unit tests for authentication binding behavior.
- README, changelog, and docs updates.

## Out Of Scope

- ASP.NET Core authentication scheme registration.
- Cookie authentication setup.
- JWT bearer authentication setup.
- OpenID Connect challenge/login setup.
- Entra ID, Auth0, Keycloak, Okta, or provider-specific adapters.
- Microsoft Graph or directory lookup.
- Authorization evaluation.
- EF Core persistence.
- Admin UI.
- Invitations.

## Proposed Architecture

### Subject Resolver

Introduce a resolver contract that turns a `ClaimsPrincipal` into a resolution result.

Conceptual shape:

```csharp
public interface IWolfAuthSubjectResolver
{
    ValueTask<WolfAuthSubjectResolutionResult> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);
}
```

The default implementation should be claim-driven:

```text
ClaimsPrincipal -> configured claim mapping -> WolfAuthSubjectResolutionResult -> WolfAuthSubject
```

### Resolution Result

The resolver should avoid throwing for normal auth states such as anonymous users or missing claims.

Conceptual states:

- resolved
- unauthenticated
- missing required claim
- invalid mapping

Conceptual shape:

```csharp
public sealed record WolfAuthSubjectResolutionResult
{
    public bool Succeeded { get; init; }
    public WolfAuthSubject? Subject { get; init; }
    public WolfAuthSubjectResolutionFailureReason? FailureReason { get; init; }
    public string? Message { get; init; }
}
```

### Claim Mapping Options

Add configurable mapping options.

Conceptual shape:

```csharp
public sealed class WolfAuthClaimsPrincipalMappingOptions
{
    public WolfAuthProviderKey DefaultProvider { get; set; } = new("default");
    public string? ProviderClaimType { get; set; }
    public List<string> SubjectIdClaimTypes { get; } = [];
    public List<string> ExternalUserIdClaimTypes { get; } = [];
    public List<string> DisplayNameClaimTypes { get; } = [];
    public List<string> EmailClaimTypes { get; } = [];
    public List<string> UserPrincipalNameClaimTypes { get; } = [];
    public List<string> GroupClaimTypes { get; } = [];
    public bool IncludeAllClaims { get; set; } = true;
}
```

Recommended default claim type candidates:

| Field | Candidate claim types |
| --- | --- |
| Subject id | `sub`, `nameidentifier`, `oid` |
| External user id | `sub`, `oid`, `nameidentifier` |
| Display name | `name`, `given_name`, `preferred_username` |
| Email | `email`, `upn`, `preferred_username` |
| UPN | `upn`, `preferred_username`, `email` |
| Groups | `groups`, `group`, `roles` only if explicitly configured |

### Provider Resolution

Provider should come from:

1. configured `ProviderClaimType`, when present and claim exists
2. configured `DefaultProvider`

Provider-specific packages can later set these defaults for Entra ID, Auth0, Keycloak, or Okta.

### Group Extraction

Groups should be mapped into `WolfAuthExternalGroup`.

Rules:

- group id comes from the configured group claim value
- provider comes from the resolved provider
- display name is optional
- no directory lookup happens in this iteration

### Local Development Factory

Add a small factory for tests and demos. This follows the WolfAuth convention of interface plus implementation instead of static helper classes.

Conceptual shape:

```csharp
public interface IWolfAuthDevelopmentSubjectFactory
{
    WolfAuthSubject Create(WolfAuthDevelopmentSubjectRequest request);
}

public sealed class WolfAuthDevelopmentSubjectFactory : IWolfAuthDevelopmentSubjectFactory
{
    public WolfAuthSubject Create(WolfAuthDevelopmentSubjectRequest request);
}
```

This is not a real authentication provider. It only creates normalized subjects for local wiring and tests.

## Deliverables

### 1. Subject Resolution Contracts

Add:

- `IWolfAuthSubjectResolver`
- `WolfAuthSubjectResolutionResult`
- `WolfAuthSubjectResolutionFailureReason`

Requirements:

- XML summaries on all public APIs.
- Normal anonymous state returns a failed result, not an exception.
- Missing required claims return stable failure reasons.

### 2. ClaimsPrincipal Resolver

Add:

- `WolfAuthClaimsPrincipalSubjectResolver`
- `WolfAuthClaimsPrincipalMappingOptions`
- claim lookup helpers, internal if possible

Requirements:

- map authenticated principals to `WolfAuthSubject`
- preserve configured claims
- extract external groups
- support provider from claim or default option

### 3. Local Development Subject Helper

Add:

- local/dev subject creation helper

Requirements:

- useful in tests and demos
- no ASP.NET Core dependency
- clearly documented as development/test support

### 4. Test Project Or Test Expansion

If no test project exists yet, add:

```text
tests/
  WolfAuth.Tests/
```

Required tests:

- anonymous principal returns unauthenticated result
- missing subject id returns missing required claim result
- default provider is used when no provider claim is configured
- provider claim overrides default provider when configured
- email, display name, and UPN map from configured claims
- groups map into `WolfAuthExternalGroup`
- claims are preserved when `IncludeAllClaims = true`
- claims are omitted when `IncludeAllClaims = false`
- development subject factory creates a valid `WolfAuthSubject`

### 5. Documentation Updates

Update:

- `README.md`
- `CHANGELOG.md`
- roadmap links

## Implementation Steps

### Step 1: Test Project Skeleton

Create the test project and add it to the solution.

Acceptance:

- `dotnet test WolfAuth.sln --configuration Release` runs.
- The first useful subject resolution tests are present immediately.

### Step 2: Resolution Result And Options

Implement result types and mapping options.

Acceptance:

- result type supports success and stable failure reasons.
- options contain default claim type candidates.
- public APIs have XML summaries.

### Step 3: ClaimsPrincipal Resolver

Implement the default resolver.

Acceptance:

- authenticated principals map to subjects.
- anonymous principals fail without throwing.
- required identifiers are validated.
- groups are extracted.

### Step 4: Development Subject Helper

Implement the local/dev helper.

Acceptance:

- tests can create subjects without manually constructing every required property.
- helper is clearly documented as non-authentication infrastructure.

### Step 5: Hardening Pass

Review public API shape, XML summaries, nullability, package output, and docs.

Acceptance:

- build has zero warnings.
- tests pass.
- package includes XML documentation.
- docs reflect the implemented MVP.

## Acceptance Criteria

Iteration 1 is complete when:

- `ClaimsPrincipal` can be resolved into `WolfAuthSubject`.
- resolution failures are explicit and stable.
- configurable claim mapping works.
- external groups can be extracted from claims.
- all new public APIs have XML summaries.
- `dotnet test WolfAuth.sln --configuration Release` passes.
- `dotnet pack WolfAuth.sln --configuration Release --no-build` includes XML docs.
- no ASP.NET Core, provider-specific, persistence, invitation, UI, or authorization evaluator dependency is introduced.

## Implemented Artifacts

- Subject resolver contract under `src/WolfAuth/Authentication/IWolfAuthSubjectResolver.cs`.
- Subject resolution result and stable failure reasons under `src/WolfAuth/Authentication/WolfAuthSubjectResolutionResult.cs`.
- Claims principal mapping options under `src/WolfAuth/Authentication/WolfAuthClaimsPrincipalMappingOptions.cs`.
- Claims principal resolver under `src/WolfAuth/Authentication/WolfAuthClaimsPrincipalSubjectResolver.cs`.
- Development subject factory interface and implementation under `src/WolfAuth/Development`.
- Authentication binding tests under `tests/WolfAuth.Tests`.

## Open Decisions Before Implementation

- Whether `SubjectId` should default to the external user id when no dedicated subject id claim exists.
- Whether `roles` should ever be treated as groups by default.
- Whether provider values should be normalized to lowercase.
- Whether missing email should be allowed.
- Whether the dev subject factory should live under a `Development` namespace.

## Recommended Defaults

- Allow `SubjectId` to default to external user id for the MVP when both map from the same stable claim.
- Do not treat `roles` as groups by default; let hosts opt in.
- Preserve provider values exactly except trimming whitespace.
- Allow missing email; require only provider, external user id, and subject id.
- Keep the dev factory in the main namespace for early ergonomics, with clear XML documentation.
