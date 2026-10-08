# Iteration 0 Contracts

Date: 2026-10-07

## Purpose

This document captures the first compiled WolfAuth contract surface. The contracts are intentionally provider-agnostic and storage-agnostic. They define the language that later packages will implement for ASP.NET Core, EF Core, Entra ID, Graph, invitations, and admin UI.

## Package Boundary

Iteration 0 keeps the contract surface in the `WolfAuth` package.

Recommended next step:

- Keep `WolfAuth` as the only package while the core evaluator is still small.
- Split `WolfAuth.Abstractions` only when another package needs to depend on the contracts without depending on the implementation.

## Key Types

WolfAuth uses typed key wrappers to avoid mixing unrelated identifiers while keeping host registration ergonomic.

| Key | Purpose |
| --- | --- |
| `WolfAuthSubjectId` | Stable product-side subject identity |
| `WolfAuthProviderKey` | External identity provider key, such as `entra-id` or `local-dev` |
| `WolfAuthExternalUserId` | Provider-side user identity |
| `WolfAuthExternalGroupKey` | Provider-side group identity |
| `WolfAuthPermissionKey` | Host-owned atomic permission key |
| `WolfAuthRoleKey` | Host-owned role key |
| `WolfAuthScopeKey` | Authorization scope key |
| `WolfAuthPolicyKey` | Host-owned policy key |

All keys reject null, empty, and whitespace-only values.

## Subject Contract

`WolfAuthSubject` is the normalized authenticated identity passed into authorization.

It includes:

- `SubjectId`
- `Provider`
- `ExternalUserId`
- `DisplayName`
- `Email`
- `UserPrincipalName`
- `Claims`
- `Groups`

The subject contract does not imply access. Access still depends on `RequireKnownSubject`, assignments, roles, scopes, policies, bootstrap administrators, and default access settings.

## Permission Contract

`WolfAuthPermission` represents an atomic host-defined action.

Metadata includes:

- Display name.
- Description.
- Category.
- Risk level.
- Tags.

Risk levels are informational in Iteration 0. Later UI and review workflows can use them to highlight sensitive permissions.

## Role Contract

`WolfAuthRole` groups permission grants.

Role inheritance is intentionally deferred. A role contains permission grants directly, and each grant may be scoped.

Recommended V1 default:

- Do not allow roles inside roles.
- Keep role expansion predictable.
- Add role inheritance later only if a real host workflow requires it.

## Scope Contract

`WolfAuthScope` limits a grant to a context.

`WolfAuthScopeKey.Global` means the permission applies globally.

Recommended V1 matching:

- `global` matches every scope.
- Non-global scopes match by exact key.
- Hierarchical scope matching is deferred.
- Unknown scopes are not auto-created during evaluation.

## Assignment Contract

`WolfAuthAssignment` represents a durable grant instruction.

Targets:

- Subject.
- External group.
- Default authenticated subject.
- Bootstrap administrator.

Grant kinds:

- Permission.
- Role.

Both direct permission assignments and role assignments can be scoped.

## Policy Contract

`WolfAuthPolicy` names a host-defined rule.

Policies may declare required permissions, but actual policy logic is expected to come from host-provided `IWolfAuthPolicyEvaluator` implementations in early versions.

Recommended V1 default:

- Policies are first-class keys and metadata.
- Policy logic is code-driven.
- Persisted policy expression languages are deferred.

## Effective Access Contract

`WolfAuthEffectiveAccess` is the expanded view of a subject's access.

It contains:

- Subject.
- Known-subject state.
- Role keys.
- Permission grants.
- External groups.
- Evaluation timestamp.

It also provides `HasPermission(permissionKey, scopeKey)` for simple checks. The method uses the V1 scope rule: global grants match all scopes, and scoped grants match only the requested scope.

## Evaluation Contract

`IWolfAuthEvaluator` defines the primary evaluation surface:

```csharp
ValueTask<WolfAuthEvaluationResult> CanAsync(
    WolfAuthEvaluationContext context,
    CancellationToken cancellationToken = default);

ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
    WolfAuthSubject subject,
    CancellationToken cancellationToken = default);
```

`WolfAuthEvaluationContext` supports:

- Permission checks.
- Policy checks.
- Scope.
- Optional resource.
- Optional host-provided items.

`WolfAuthEvaluationResult` returns:

- Allow or deny.
- Stable reason code.
- Required permission or policy key.
- Scope.
- Optional role.
- Optional effective access snapshot.
- Diagnostics.

Stable reason codes are part of the contract because UI, APIs, logs, and tests need predictable outcomes.

## Permission Registry

`WolfAuthPermissionRegistryBuilder` is the host registration surface for Iteration 0.

It supports:

- Permission registration.
- Role registration.
- Policy registration.
- Scoped role permission grants.
- Duplicate key detection.
- Read-only registry build output.

Example:

```csharp
var registry = new WolfAuthPermissionRegistryBuilder()
    .AddPermission("contracts.events.view", displayName: "View events", category: "Contracts")
    .AddPermission("contracts.events.version.create", displayName: "Create event versions", category: "Contracts")
    .AddRole("designer", role =>
    {
        role.DisplayName = "Designer";
        role.AddPermission("contracts.events.view");
        role.AddPermission("contracts.events.version.create");
    })
    .Build();
```

Duplicate registrations throw `WolfAuthDuplicateRegistrationException`.

## Options

`WolfAuthOptions` contains MVP-level configuration:

- `RequireKnownSubject`
- `DefaultAuthenticatedRoleKeys`
- `BootstrapAdministrators`

Recommended default:

```text
RequireKnownSubject = true
```

Bootstrap administrators are modeled as seed input rather than startup-only magic. This keeps the path open for audited, durable assignments in later iterations.

## Deferred Decisions

The following are intentionally deferred:

- EF Core entity design.
- ASP.NET Core attributes and endpoint metadata.
- Directory lookup contracts.
- Invitation contracts.
- Deny rules.
- Hierarchical scopes.
- Role inheritance.
- Persisted policy expression language.
- Multi-tenant storage layout.
