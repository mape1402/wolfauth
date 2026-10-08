# Iteration 0 Acceptance Scenarios

Date: 2026-10-07

These scenarios define the first unit test matrix for the Core Authorization MVP. Iteration 0 provides the contracts and expected behavior; Iteration 2 should turn these scenarios into executable tests against the first evaluator implementation.

## Test Matrix

| Scenario | Setup | Evaluation | Expected Result |
| --- | --- | --- | --- |
| `CanAsync_DeniesUnknownSubject_WhenKnownSubjectsAreRequired` | `RequireKnownSubject = true`; authenticated subject has no local assignment | Check `contracts.events.view` | Denied with `DeniedUnknownSubject` |
| `CanAsync_AllowsDefaultAccess_WhenKnownSubjectsAreNotRequired` | `RequireKnownSubject = false`; default authenticated role grants `contracts.events.view` | Check `contracts.events.view` | Allowed with `AllowedByDefaultRole` |
| `CanAsync_AllowsDirectPermission` | Known subject has direct permission `contracts.events.view` in `global` | Check `contracts.events.view` | Allowed with `AllowedByDirectPermission` |
| `CanAsync_AllowsRolePermission` | Known subject has role `designer`; role grants `contracts.events.version.create` | Check `contracts.events.version.create` | Allowed with `AllowedByRole` |
| `CanAsync_DeniesMissingPermission` | Known subject has no matching direct, role, group, default, or bootstrap grant | Check `contracts.events.delete` | Denied with `DeniedMissingPermission` |
| `CanAsync_DeniesPermissionOutsideScope` | Known subject has `distribution.releases.deploy` scoped to `environment:qa` | Check `distribution.releases.deploy` for `environment:production` | Denied with `DeniedScopeMismatch` |
| `CanAsync_AllowsExternalGroupMappedRole` | Subject has external group `KnOwl-Reviewers`; group maps to internal `reviewer` role | Check permission granted by `reviewer` | Allowed with `AllowedByExternalGroup` |
| `CanAsync_AllowsBootstrapAdministrator` | Subject matches configured bootstrap administrator; administrator role grants security permissions | Check `security.roles.manage` | Allowed with `AllowedByBootstrapAdministrator` |
| `CanAsync_DeniesUnknownPermission` | Requested permission is absent from the host registry | Check `unknown.permission` | Denied with `DeniedUnknownPermission` |
| `CanAsync_DeniesUnregisteredPolicy` | Requested policy is absent from the host registry | Check policy `events.promote` | Denied with `DeniedPolicyNotRegistered` |
| `CanAsync_DeniesFailedPolicy` | Registered policy evaluator returns false | Check policy `events.promote` with invalid resource state | Denied with `DeniedPolicyFailed` |
| `GetEffectiveAccess_ReturnsExpandedAccess` | Subject has direct, role, external group, and bootstrap/default-derived grants | Request effective access | Result includes role keys, permission grants, external groups, known-subject state, and timestamp |

## Scope Expectations

Scope behavior for the MVP should be exact and predictable:

- A `global` grant satisfies checks for any scope.
- A scoped grant satisfies only checks for the same scope key.
- A scoped grant does not satisfy `global`.
- Unknown requested scopes do not create access by themselves.

## Registry Expectations

The registry should guarantee deterministic host startup behavior:

- Duplicate permission keys fail during registration.
- Duplicate role keys fail during registration.
- Duplicate policy keys fail during registration.
- Registry reads are case-sensitive unless a future host requirement proves otherwise.
- The registry can be queried by APIs and admin UI without referencing persistence.

## Result Reason Expectations

Every deny path must return a stable reason code. Messages may change, but reason values should remain stable enough for:

- Unit tests.
- API clients.
- Admin UI hints.
- Audit and diagnostics.

## Non-Goals For The First Test Suite

- EF Core persistence tests.
- ASP.NET Core endpoint tests.
- Provider-specific claims mapping tests.
- Directory search tests.
- Invitation flow tests.
- Email sender tests.
- UI rendering tests.
