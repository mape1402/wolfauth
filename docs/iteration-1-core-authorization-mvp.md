# Iteration 1: Core Authorization MVP

Date: 2026-10-07

## Objective

Implement the first functional WolfAuth authorization core in memory.

Iteration 0 defined provider-agnostic contracts and acceptance scenarios. Iteration 1 should make those contracts executable with a deterministic in-memory evaluator, focused unit tests, XML documentation on all public code, and no dependency on ASP.NET Core, EF Core, Entra ID, Graph, invitations, or admin UI.

## Outcome

At the end of this iteration, a host should be able to:

- Register permissions, roles, and policies.
- Configure `RequireKnownSubject`.
- Provide known subjects and assignments through an in-memory store.
- Expand effective access for a subject.
- Evaluate permission checks with stable reason codes.
- Evaluate host policies through registered policy evaluators.
- Run a meaningful test suite that proves the Core Authorization MVP behavior.

## Guiding Principles

- Keep the core deterministic, small, and storage-agnostic.
- Preserve the existing public contract style and XML documentation standard.
- Make behavior observable through stable `WolfAuthEvaluationReason` values.
- Prefer explicit store/evaluator boundaries over hidden global state.
- Defer framework integration until the core is proven by tests.
- Keep scope matching simple: `global` applies everywhere; non-global scopes match exactly.

## In Scope

- In-memory authorization data store.
- Known subject resolution.
- Subject assignments.
- Default authenticated role assignments.
- Bootstrap administrator matching.
- External group to internal role expansion.
- Effective access expansion.
- Permission evaluation.
- Policy evaluation dispatch through `IWolfAuthPolicyEvaluator`.
- Test project and unit tests for the Iteration 0 acceptance matrix.
- XML documentation summaries for all new public APIs.
- README, changelog, and docs updates.

## Out Of Scope

- EF Core persistence.
- ASP.NET Core dependency injection package.
- ASP.NET Core attributes, filters, middleware, endpoint metadata, or Razor helpers.
- Entra ID, Graph, Auth0, Keycloak, Okta, or OIDC adapters.
- Directory search.
- Invitations and email senders.
- Admin UI.
- Audit log persistence.
- Deny rules.
- Hierarchical scopes.
- Role inheritance.
- Persisted policy expression language.

## Proposed Architecture

### Authorization Store

Introduce a read-only store contract for evaluator input.

Conceptual shape:

```csharp
public interface IWolfAuthAuthorizationStore
{
    ValueTask<bool> IsKnownSubjectAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<WolfAuthAssignment>> GetAssignmentsAsync(
        WolfAuthSubject subject,
        CancellationToken cancellationToken = default);
}
```

The MVP implementation can be an in-memory store backed by immutable collections or defensive copies.

### External Group Mapping

External group mappings should be represented as assignments where:

- `TargetKind = ExternalGroup`
- `ExternalGroupKey` matches a group on the subject.
- `GrantKind = Role` or `Permission`

This keeps group mapping inside the same assignment expansion pipeline.

### Default Authenticated Access

Default access should be represented as assignments where:

- `TargetKind = DefaultAuthenticatedSubject`
- `GrantKind = Role` or `Permission`

These assignments apply only when:

- `RequireKnownSubject = false`
- the subject is authenticated
- the subject has no known-subject requirement failure

### Bootstrap Administrators

Bootstrap administrators should expand into a role grant when a subject matches any configured bootstrap rule by:

- `SubjectId`
- provider plus `ExternalUserId`
- email

Matching should be case-insensitive for email and exact for identifiers.

### Effective Access Builder

Introduce an internal or public component that expands access from:

- direct subject assignments
- role assignments
- default authenticated assignments
- external group assignments
- bootstrap administrator seed rules
- role definitions from the registry

The result is a `WolfAuthEffectiveAccess` instance.

### Evaluator

Implement `WolfAuthEvaluator : IWolfAuthEvaluator`.

Permission flow:

1. Validate the context.
2. Ensure requested permission exists in the registry.
3. Expand effective access.
4. Apply `RequireKnownSubject`.
5. Check direct, role, group, default, and bootstrap grants.
6. Return the most specific stable reason code.

Policy flow:

1. Validate the context.
2. Ensure requested policy exists in the registry.
3. Ensure required permissions pass, when defined.
4. Dispatch to a matching `IWolfAuthPolicyEvaluator`.
5. Return `DeniedPolicyNotRegistered` or `DeniedPolicyFailed` when appropriate.

## Deliverables

### 1. Store Contracts And In-Memory Store

Add:

- `IWolfAuthAuthorizationStore`
- `WolfAuthInMemoryAuthorizationStore`
- optional builder/seed type for test and host ergonomics

Requirements:

- Store known subjects.
- Store assignments.
- Return defensive read-only data.
- Stay framework-independent.
- Include XML summaries.

### 2. Effective Access Expansion

Add:

- access expansion logic
- role expansion logic
- scope preservation
- group assignment matching
- default authenticated assignment matching
- bootstrap administrator matching

Requirements:

- no role inheritance in V1
- no deny rules in V1
- no persistence concerns

### 3. Core Evaluator

Add:

- `WolfAuthEvaluator`
- permission evaluation
- policy evaluation dispatch
- stable reason selection
- invalid request handling

Requirements:

- return `DeniedUnknownSubject` when appropriate
- return `DeniedUnknownPermission` for unregistered permissions
- return `DeniedMissingPermission` when no grant exists
- return `DeniedScopeMismatch` when a grant exists for a different scope
- return allowed reasons based on grant source

### 4. Test Project

Add a test project under:

```text
tests/
  WolfAuth.Tests/
```

Preferred stack:

- xUnit
- FluentAssertions if already acceptable, otherwise plain xUnit assertions

Required tests should cover the matrix from `docs/iteration-0-acceptance-scenarios.md`.

### 5. Documentation Updates

Update:

- `README.md`
- `CHANGELOG.md`
- Iteration 1 plan status

All new public code must include XML documentation summaries, and the package must continue to include XML docs.

## Implementation Steps

### Step 1: Test Project Skeleton

Create the test project and add it to the solution.

Acceptance:

- `dotnet test WolfAuth.sln --configuration Release` runs.
- Empty or placeholder tests are avoided; the first useful evaluator tests are added immediately.

### Step 2: Store Contract And In-Memory Store

Implement store contracts and in-memory data setup helpers.

Acceptance:

- Tests can seed known subjects and assignments without framework dependencies.

### Step 3: Effective Access Expansion

Implement effective access calculation.

Acceptance:

- Direct permission grants appear in effective access.
- Role permission grants appear in effective access.
- External group role grants appear in effective access.
- Default authenticated grants appear only when configured.
- Bootstrap admin grants appear when a subject matches.

### Step 4: Permission Evaluation

Implement `CanAsync` for permission checks.

Acceptance:

- Required permission scenarios pass.
- Unknown permission and scope mismatch scenarios return stable reasons.

### Step 5: Policy Evaluation

Implement policy registration and evaluator dispatch.

Acceptance:

- unregistered policies return `DeniedPolicyNotRegistered`
- failed policies return `DeniedPolicyFailed`
- passing policies can return allowed results

### Step 6: Hardening Pass

Review public API shape, XML summaries, nullability, and package output.

Acceptance:

- build has zero warnings
- tests pass
- package includes XML documentation
- docs reflect the implemented MVP

## Acceptance Criteria

Iteration 1 is complete when:

- The in-memory authorization core compiles across `net8.0`, `net9.0`, and `net10.0`.
- The test suite covers all required Iteration 0 acceptance scenarios.
- `dotnet test WolfAuth.sln --configuration Release` passes.
- `dotnet pack WolfAuth.sln --configuration Release --no-build` includes XML docs.
- All public APIs introduced in Iteration 1 have XML summaries.
- No ASP.NET Core, EF Core, provider-specific, invitation, or admin UI dependency is introduced.

## Required Test Names

Use these names unless the implementation reveals a clearer local convention:

- `CanAsync_DeniesUnknownSubject_WhenKnownSubjectsAreRequired`
- `CanAsync_AllowsDefaultAccess_WhenKnownSubjectsAreNotRequired`
- `CanAsync_AllowsDirectPermission`
- `CanAsync_AllowsRolePermission`
- `CanAsync_DeniesMissingPermission`
- `CanAsync_DeniesPermissionOutsideScope`
- `CanAsync_AllowsExternalGroupMappedRole`
- `CanAsync_AllowsBootstrapAdministrator`
- `CanAsync_DeniesUnknownPermission`
- `CanAsync_DeniesUnregisteredPolicy`
- `CanAsync_DeniesFailedPolicy`
- `GetEffectiveAccess_ReturnsExpandedAccess`

## Open Decisions Before Implementation

- Whether `IWolfAuthAuthorizationStore` should accept `WolfAuthSubject` or `WolfAuthSubjectId` for assignment lookups.
- Whether in-memory seed APIs should live directly in the main package or remain test-oriented.
- Whether policy evaluators should be passed as an enumerable to `WolfAuthEvaluator` or wrapped in a registry.
- Whether default authenticated access is configured only through assignments or also through `WolfAuthOptions.DefaultAuthenticatedRoleKeys`.
- Whether `DeniedScopeMismatch` should be returned only when the requested permission exists in another scope, or also when the subject has any grant in another scope.

## Recommended Defaults

- Use `WolfAuthSubject` for store lookups so bootstrap and provider matching remain straightforward.
- Keep the in-memory store in the main package because it is useful for tests, demos, local development, and hosts that do not need persistence.
- Pass policy evaluators as an enumerable and index them by `PolicyKey` inside the evaluator.
- Support both default authenticated assignments and `WolfAuthOptions.DefaultAuthenticatedRoleKeys`.
- Return `DeniedScopeMismatch` only when the same permission exists for the subject in a different non-matching scope.
