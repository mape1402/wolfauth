# Iteration 0: Product And Contract Spike

Date: 2026-10-07

## Objective

Define the smallest stable WolfAuth authorization contract before building production integrations.

This iteration should turn the product strategy into concrete, reviewable contracts for subjects, permissions, roles, scopes, assignments, policies, effective access, and host registration. The result should be strong enough to guide the first implementation slice without committing the project too early to ASP.NET Core, EF Core, Entra ID, Graph, or an admin UI.

## Guiding Principles

- External providers authenticate users; WolfAuth authorizes product access.
- The core model must stay independent from ASP.NET Core, EF Core, and provider-specific SDKs.
- Permission checks must work for endpoints, page handlers, UI actions, backend commands, and resource-state decisions.
- The backend is always the source of truth, even when UI helpers hide or disable actions.
- Hosts own their permission catalogs and default roles; WolfAuth owns the model, evaluator contracts, and enforcement pattern.

## In Scope

- Draft the core authorization vocabulary.
- Define the minimum subject identity contract.
- Define permission keys and permission metadata.
- Define role composition.
- Define direct and role-based assignments.
- Define scope identity and scope matching semantics.
- Define an effective permission result shape.
- Define the evaluator interface shape for `Can` and `Require` flows.
- Define the host permission registry contract.
- Define `RequireKnownSubject` behavior.
- Define bootstrap administrator seed input shape.
- Capture open decisions for later iterations.

## Out Of Scope

- EF Core persistence.
- ASP.NET Core attributes, filters, middleware, or endpoint metadata.
- Reusable admin UI.
- Entra ID, Microsoft Graph, Auth0, Keycloak, Okta, or OIDC provider implementations.
- Invitation acceptance flows.
- Email sender implementations.
- Production audit logging.
- Multi-tenant storage design.

## Deliverables

### 1. Core Contract Draft

Create draft contracts for:

- `WolfAuthSubject`
- `WolfAuthClaim`
- `WolfAuthExternalGroup`
- `WolfAuthPermission`
- `WolfAuthRole`
- `WolfAuthScope`
- `WolfAuthAssignment`
- `WolfAuthPolicy`
- `WolfAuthEffectiveAccess`
- `WolfAuthEvaluationContext`
- `WolfAuthEvaluationResult`

The contract draft may start as Markdown, C# records/interfaces, or both. If code is introduced, it should compile and stay provider-agnostic.

### 2. Permission Registry Draft

Define how a host registers its permission catalog.

The draft should answer:

- How does a host define a permission key?
- How are display names, descriptions, categories, and risk levels represented?
- How are default roles registered?
- How can duplicate permission keys be detected?
- How can the registry be queried by admin UI and APIs later?

### 3. Assignment And Scope Semantics

Define how assignments apply.

The draft should answer:

- Can permissions be assigned directly to subjects?
- Can roles be scoped?
- Can direct permissions be scoped?
- What does a global scope mean?
- How are unknown scopes handled?
- How are external groups mapped to internal roles?
- How are deny rules handled, if at all, in the first version?

### 4. Evaluator Contract Draft

Define the initial evaluator surface.

Conceptual shape:

```csharp
ValueTask<WolfAuthEvaluationResult> CanAsync(
    WolfAuthEvaluationContext context,
    CancellationToken cancellationToken);

ValueTask<WolfAuthEffectiveAccess> GetEffectiveAccessAsync(
    WolfAuthSubject subject,
    CancellationToken cancellationToken);
```

The draft should cover:

- Permission checks.
- Permission plus resource checks.
- Policy checks.
- Known subject enforcement.
- Missing permission behavior.
- Scoped access behavior.
- Result reasons for diagnostics and UI.

### 5. Host Integration Sketch

Define the target developer experience for hosts.

Conceptual shape:

```csharp
services.AddWolfAuth(options =>
{
    options.RequireKnownSubject = true;
});

services.AddWolfAuthPermissions(registry =>
{
    registry.AddPermission("contracts.events.view");
    registry.AddRole("Designer", role =>
    {
        role.AddPermission("contracts.events.view");
        role.AddPermission("contracts.events.version.create");
    });
});
```

This sketch is not the final ASP.NET Core implementation. It is the design target that later packages should satisfy.

### 6. Acceptance Test Scenarios

Write scenario definitions for the first unit test suite.

Required scenarios:

- Unknown authenticated subject is denied when `RequireKnownSubject` is true.
- Unknown authenticated subject receives default access when `RequireKnownSubject` is false and defaults are configured.
- Subject with direct permission can execute the matching action.
- Subject with role permission can execute the matching action.
- Subject without permission is denied with a stable reason.
- Subject with QA-scoped permission cannot use it in Production.
- External group mapping grants the mapped internal role.
- Bootstrap administrator receives administrator access.

## Proposed Work Plan

### Step 1: Vocabulary And Boundaries

Create a short design document that names the core concepts and defines what each concept owns.

Output:

- Contract vocabulary.
- Boundary notes.
- Explicit non-goals.

### Step 2: Contract Shapes

Draft the first C#-friendly shapes for subjects, permissions, roles, scopes, assignments, effective access, and evaluation results.

Output:

- Contract draft.
- Notes for nullable fields and identity keys.
- Notes for immutable versus mutable data.

### Step 3: Evaluation Semantics

Define how a permission check is evaluated from subject identity, local assignments, role assignments, external group mappings, and scopes.

Output:

- Evaluation flow.
- Result reason taxonomy.
- Scope matching rules.

### Step 4: Host Registration Semantics

Define how hosts contribute permissions and default roles.

Output:

- Permission registry draft.
- Duplicate key behavior.
- Default role seed behavior.

### Step 5: Test Plan

Turn acceptance scenarios into a test matrix for the first implementation iteration.

Output:

- Unit test names.
- Expected setup.
- Expected result.

## Key Decisions To Make

- Whether the first implementation package remains `WolfAuth` only or splits immediately into `WolfAuth.Abstractions` and `WolfAuth`.
- Whether permission keys are plain strings, strongly typed wrappers, or both.
- Whether deny rules exist in V1 or are deferred.
- Whether scopes are hierarchical in V1 or exact-match only.
- Whether policies are first-class persisted records in V1 or host-provided evaluators.
- Whether roles can include other roles in V1.
- Whether bootstrap administrators are modeled as seed assignments or a startup-only grant.

## Completion Criteria

Iteration 0 is complete when:

- The core vocabulary is documented.
- The first contract shapes are documented or compiled.
- The evaluator surface is clear enough to implement.
- Scope and assignment semantics are unambiguous for MVP scenarios.
- Host registration has a target developer experience.
- Acceptance test scenarios are ready for Iteration 1.
- Open decisions are captured with recommended defaults.

## Recommended Defaults

- Keep one package for the spike, then split only when code starts to justify it.
- Use strongly typed wrappers around permission keys and scope keys while preserving string conversion for host ergonomics.
- Defer deny rules until allow-only semantics are proven.
- Use exact scope matching plus a `Global` scope for MVP.
- Treat policies as host-provided evaluators in early versions.
- Do not allow role inheritance in V1.
- Model bootstrap administrators as seed assignments so behavior is auditable later.
