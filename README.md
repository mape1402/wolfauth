<p align="center">
  <img src="assets/wolfauth-logo.png" alt="WolfAuth logo" width="360" />
</p>

# WolfAuth

WolfAuth is the Elysium library for centralized authentication integration, authorization, and access provisioning across Web UIs and APIs.

It is not an identity provider. External systems such as Microsoft Entra ID, Auth0, Keycloak, Okta, or any OpenID Connect provider can authenticate users, while WolfAuth owns product-level access, roles, permissions, policies, scopes, invitations, and administrative provisioning.

```text
external identity -> normalized subject -> internal authorization -> enforced product access
```

WolfAuth should let products such as KnOwl, Krackend Orchestrator, and future Elysium hosts activate serious access control with a shared model, while each host keeps control over its own permissions, policies, resources, and UI behavior.

## North Star

WolfAuth should become the standard Elysium access layer for products that need reusable security without surrendering fine-grained product authorization to an external directory.

Design mantra:

```text
Identity proves who the user is. Authorization decides what the product allows.
```

## Core Principle

The external provider should not dictate all internal product security.

The identity provider answers:

- Who the user is.
- Which external identity the user has.
- Which claims were issued.
- Which groups may be present in the token.
- Which users or groups may exist in the directory, when a directory API is configured.

WolfAuth answers:

- Whether the authenticated subject is allowed into the host.
- Which internal roles the subject has.
- Which effective permissions the subject has.
- Which policies the subject satisfies.
- Which scopes or resources the access applies to.
- Which product actions the subject can execute.

The host answers:

- Which permissions exist.
- Which default roles exist.
- Which policies are required.
- Which resources need special rules.
- Which administration surface should be exposed.

## Conceptual Architecture

WolfAuth is designed around clear boundaries:

| Layer | Responsibility |
| --- | --- |
| Identity Adapter | Normalize the authenticated subject from external or local auth providers |
| Directory Adapter | Optionally search and resolve users or groups from an external directory |
| Authorization Core | Model users, roles, permissions, assignments, scopes, policies, and effective access |
| Authorization Store | Persist users, roles, invitations, group mappings, audit logs, and assignments |
| Policy Evaluator | Evaluate permission, role, claim, scope, and resource-state rules |
| Host Permission Registry | Let each host register its own permission catalog and default roles |
| Admin UI | Provide reusable user, role, invitation, group, and audit management screens |
| API Enforcement | Protect endpoints, handlers, application commands, and resource actions |
| Frontend Contract | Expose security state to SPAs and UI components without making the frontend the source of truth |

## Authentication

WolfAuth should support pluggable identity adapters. The adapter only authenticates and normalizes identity; it does not decide product authorization.

Candidate adapters:

- Microsoft Entra ID.
- Auth0.
- Keycloak.
- Okta.
- Generic OpenID Connect.
- JWT bearer.
- Cookie authentication.
- Local development authentication.

Normalized subjects should expose:

```text
SubjectId
Provider
ExternalUserId
DisplayName
Email
UserPrincipalName
Claims
Groups
```

## Directory Lookup

Directory adapters are optional. They enable administrator workflows where a product can search for users or groups before granting access.

Candidate directory adapters:

- Microsoft Graph for Entra ID.
- SCIM-compatible providers.
- LDAP or Active Directory.
- Proprietary directory APIs.
- Manual or local directory storage.

Directory lookup should support:

- User search.
- Group search.
- User resolution by email.
- User resolution by external id.
- Optional group and membership resolution.

Authenticating with Entra ID does not automatically mean the product can list tenant users. Directory search requires Microsoft Graph and the right permissions.

## Authorization Model

WolfAuth authorization should be independent from the UI technology. The same model should protect Razor Pages, MVC, APIs, Blazor, Angular, React, Vue, background workers, and internal application commands.

The core model includes:

- Known subjects.
- Roles.
- Permissions.
- Direct assignments.
- Policy rules.
- Scopes.
- External group mappings.
- Effective permission evaluation.

## Permissions

Permissions are concrete, atomic actions defined by each host.

Examples:

```text
contracts.dataTypes.view
contracts.dataTypes.create
contracts.dataTypes.edit
contracts.dataTypes.delete

contracts.events.view
contracts.events.create
contracts.events.version.create
contracts.events.version.promote

distribution.releases.view
distribution.releases.create
distribution.releases.deploy

documentation.spaces.view
documentation.spaces.create
documentation.pages.browse

security.users.view
security.users.invite
security.roles.manage
security.assignments.manage
```

KnOwl defines KnOwl permissions. Krackend Orchestrator defines Krackend permissions. WolfAuth provides the model, registry, evaluator, and enforcement tools.

## Roles

Roles are manageable collections of permissions. They can be seeded by code and administered through UI.

Examples:

```text
Administrator
Designer
Reviewer
Release Manager
Runtime Operator
Documentation Reader
```

Roles may grant global permissions or scoped permissions.

```text
Role: Release Manager
Permissions:
- distribution.releases.view
- distribution.releases.create
- distribution.releases.deploy
```

## Policies

Policies represent expressive authorization rules that cannot be captured by a simple permission alone.

Examples:

- A subject can edit a version only while it is in Draft.
- A subject can promote a version only with the required permission and when the version is in Review.
- A subject can view a resource only inside an allowed environment.
- A subject can manage users only with the Administrator role.
- A subject can execute a sensitive action only after MFA.
- A subject can approve a change only when they are not the creator.

Policies should combine:

- Permissions.
- Claims.
- Roles.
- Resource state.
- Scope.
- Host-specific rules.

## Scopes

Scopes limit access to a context.

Examples:

```text
Global
Environment: Development
Environment: QA
Environment: Production
Space: Documentation
Project: X
RuntimeNode: Y
```

This enables scenarios such as allowing a user to view QA releases but not production releases, or allowing a user to manage one documentation space but not all spaces.

## Authorization Evaluation

WolfAuth should expose a central evaluator:

```text
Can(user, permission)
Can(user, permission, resource)
Can(user, policy, resource)
GetEffectivePermissions(user)
```

The evaluator should be used by:

- Razor Pages.
- API endpoints.
- UI components.
- Buttons.
- Menus.
- Backend actions.
- Application commands.

The UI may hide or disable actions, but the backend must always enforce authorization.

## Enforcement Targets

Authorization should not be validated only against routes. Routes help, but product security also needs to protect:

- Endpoints.
- Page handlers.
- API actions.
- Application commands.
- Buttons and user actions.
- Specific resources.
- Workflow states.

Example endpoint mapping:

```text
GET /contracts/events -> contracts.events.view
POST /contracts/events -> contracts.events.create
POST /contracts/events/{id}/versions -> contracts.events.version.create
POST /contracts/events/{id}/versions/{version}/promote -> contracts.events.version.promote
```

Example UI mapping:

```text
Button: New Version -> contracts.events.version.create
Button: Promote -> contracts.events.version.promote
Button: Delete -> contracts.events.delete
```

## ASP.NET Core Integration

Razor Pages and APIs should be able to use attributes, filters, middleware, endpoint metadata, and explicit service calls.

Conceptual Razor Pages usage:

```csharp
[RequirePermission("contracts.events.view")]
public class EventsPageModel : PageModel
{
}
```

Conceptual resource action usage:

```csharp
await authorization.RequireAsync(User, "contracts.events.version.create", eventResource);
```

Conceptual API usage:

```csharp
[RequirePermission("distribution.releases.create")]
[HttpPost("/api/releases")]
public async Task<IActionResult> CreateRelease(...)
{
}
```

## SPA Contract

For Angular, React, Vue, or any other SPA, WolfAuth should expose standard endpoints:

```text
GET /api/security/me
GET /api/security/permissions
POST /api/security/can
```

Example response:

```json
{
  "subjectId": "123",
  "displayName": "Mario Perez",
  "permissions": [
    "contracts.events.view",
    "contracts.events.version.create"
  ],
  "roles": [
    "Designer"
  ]
}
```

The frontend can use this to decide what to show, but the backend remains the source of truth.

## Known Subject Requirement

WolfAuth should support a `RequireKnownSubject` option.

Recommended internal-product mode:

```text
RequireKnownSubject = true
```

In this mode:

- The user can authenticate with the external provider.
- The user still has no product access unless provisioned internally.
- The host can show an access pending or request access screen.

Open mode:

```text
RequireKnownSubject = false
```

In this mode, any authenticated user may enter with default or minimal access.

## Bootstrap Administrators

WolfAuth should provide safe ways to create the first administrators:

- Configuration by email.
- Configuration by external subject id.
- Seed from appsettings.
- First authenticated user becomes administrator only in controlled environments.
- Administrative script.

Example:

```json
{
  "WolfAuth": {
    "BootstrapAdmins": [
      "admin@company.com"
    ]
  }
}
```

## External Groups

WolfAuth should support mapping external groups to internal roles.

Example:

```text
Entra Group: KnOwl-Admins -> Role: Administrator
Entra Group: KnOwl-Reviewers -> Role: Reviewer
```

This enables hybrid administration:

- The external directory controls broad membership.
- The product controls fine-grained permissions.
- Local roles can be combined with external group mappings.
- Group resolution can query the directory when the token omits or truncates group claims.

## User Provisioning

WolfAuth should support two primary provisioning paths.

### Directory Search

When a directory adapter is configured:

1. An administrator opens Security / Users.
2. The administrator selects Add user.
3. The administrator searches by name or email.
4. WolfAuth queries the directory adapter.
5. The administrator selects a user.
6. The administrator assigns roles, permissions, and scopes.
7. The user has access after authentication.

### Invitations

When directory access is unavailable or undesirable:

1. An administrator enters an email.
2. The administrator assigns roles, permissions, and scopes.
3. WolfAuth creates a pending invitation.
4. The administrator copies a link or sends email if an invitation sender is configured.
5. The user opens the link.
6. The user authenticates through the configured identity provider.
7. WolfAuth links the external identity with the invitation.
8. The user becomes provisioned.

Invitation links do not replace authentication. They represent pending authorization only.

Invitation validation should check:

- Token validity.
- Expiration.
- Whether the invitation has already been used.
- Expected email, when applicable.
- Tenant, when applicable.
- Provider, when applicable.

Email sending should be optional behind an interface:

```csharp
public interface IInvitationSender
{
    Task SendInvitationAsync(InvitationMessage message, CancellationToken cancellationToken);
}
```

Possible senders include SMTP, SendGrid, Microsoft Graph Mail, Amazon SES, and a null sender for development.

## Reusable Admin Surface

WolfAuth may include a reusable admin UI with screens for:

- Users.
- User detail.
- Roles.
- Role detail.
- Permissions.
- Policies.
- Invitations.
- Groups.
- Audit log.

Each host should be able to:

- Mount the UI under a configured route.
- Apply product branding.
- Support dark and light modes.
- Register host permissions.
- Hide modules that are not used.

## Reusable API Surface

WolfAuth may expose reusable API endpoints:

```text
GET /api/security/me
GET /api/security/users
POST /api/security/users
GET /api/security/roles
POST /api/security/roles
POST /api/security/assignments
GET /api/security/permissions
POST /api/security/invitations
POST /api/security/can
```

Conceptual activation:

```csharp
app.MapWolfAuthApi();
```

## Proposed Package Direction

The first repository scaffold contains one packable package. As the design stabilizes, the library can split into focused packages:

Core:

```text
WolfAuth
WolfAuth.Abstractions
WolfAuth.DependencyInjection
```

ASP.NET Core and storage:

```text
WolfAuth.AspNetCore
WolfAuth.EntityFrameworkCore
WolfAuth.WebUI
WolfAuth.Api
```

Identity and directory adapters:

```text
WolfAuth.EntraId
WolfAuth.Auth0
WolfAuth.Keycloak
WolfAuth.Okta
WolfAuth.OpenIdConnect
```

Email and invitations:

```text
WolfAuth.Email.Smtp
WolfAuth.Email.SendGrid
WolfAuth.Email.Graph
WolfAuth.Email.Ses
```

## Position In Elysium

WolfAuth is designed to be shared by Elysium hosts without becoming their product model.

| Elysium piece | Relationship |
| --- | --- |
| KnOwl | Defines contract, documentation, release, and governance permissions |
| Krackend | Defines orchestration, workflow, runtime action, and operational permissions |
| Axolotl.Mesh | Defines operation execution and external system runtime permissions |
| TurtlePath | Can host WolfAuth-protected web applications and APIs |
| DataScorpio | Can query authorization catalogs, assignments, and audit data when needed |

## Recommended First Slice

Build the smallest useful authorization core before adapter or UI work:

1. Permission key model and registry.
2. Role model.
3. Subject model.
4. Scope model.
5. Direct and role-based assignments.
6. Effective permission evaluator.
7. `RequireKnownSubject` behavior.
8. Bootstrap administrator seed model.
9. Strong unit tests for permission evaluation.

This proves the heart of WolfAuth without pulling in EF Core, admin UI, Entra ID, Graph, or invitations too early.

See the detailed [Iteration 0 plan](docs/iteration-0-product-contract-spike.md).
The compiled contract notes are in [Iteration 0 contracts](docs/iteration-0-contracts.md), and the first evaluator test matrix is in [Iteration 0 acceptance scenarios](docs/iteration-0-acceptance-scenarios.md).

## Roadmap

### Iteration 0: Product And Contract Spike

Define the smallest stable authorization model before building production integrations.

Deliverables:

- Subject model draft.
- Permission model draft.
- Role model draft.
- Scope model draft.
- Assignment model draft.
- Effective permission result draft.
- Evaluator interface draft.
- Host permission registry draft.

Acceptance criteria:

- A host can register permissions and default roles.
- A subject can receive direct permissions and role assignments.
- The evaluator can answer simple and scoped `Can` checks.
- The model is independent from ASP.NET Core and EF Core.

### Iteration 1: Core Authorization MVP

Implement the core in memory with strong unit tests.

Focus areas:

- `WolfAuth.Abstractions`.
- `WolfAuth`.
- Permission keys.
- Role and assignment composition.
- Scope matching.
- Known subject enforcement.
- Effective permission calculation.

### Iteration 2: ASP.NET Core Integration

Make the core enforceable in web hosts.

Focus areas:

- Dependency injection.
- Claims principal normalization.
- Authorization attributes.
- Endpoint metadata.
- Razor helpers.
- Explicit `RequireAsync` service calls.
- Minimal API integration.

### Iteration 3: Persistence

Add durable storage.

Focus areas:

- EF Core entities.
- Migrations.
- User and role persistence.
- Direct permission assignments.
- Scoped assignments.
- External group mappings.
- Audit log.
- Bootstrap admin seeding.

### Iteration 4: Admin UI

Provide a reusable management surface.

Focus areas:

- Users.
- Roles.
- Assignments.
- Invitations.
- Group mappings.
- Audit log.
- Host branding and theming hooks.

### Iteration 5: Entra ID Adapter

Add a first provider-specific adapter.

Focus areas:

- OpenID Connect configuration helpers.
- Microsoft Graph directory adapter.
- User search.
- Group search.
- Group-to-role mapping.
- Group overage resolution.

### Iteration 6: Invitations

Support provisioning without directory search.

Focus areas:

- Invitation creation.
- Invitation acceptance.
- Expiration.
- One-time use.
- Email sender abstraction.
- Copy-link flow.

### Iteration 7: SPA/API Contract

Expose reusable API endpoints for SPAs and external clients.

Focus areas:

- `/api/security/me`.
- `/api/security/can`.
- `/api/security/permissions`.
- Administrative endpoints.

### Iteration 8: Host Integrations

Integrate WolfAuth into Elysium products.

Targets:

- KnOwl.
- Krackend Orchestrator.
- Future Elysium hosts.

## Current Repository State

This repository currently contains the initial WolfAuth contract spike:

```text
src/
  WolfAuth/
    Contracts/
    Evaluation/
    Options/
    Registry/
    WolfAuth.csproj
```

The current code defines provider-agnostic contracts, registry surfaces, evaluator interfaces, options, and documented acceptance scenarios. The next implementation step should be the Core Authorization MVP.

## Build

```bash
dotnet restore WolfAuth.sln
dotnet build WolfAuth.sln --configuration Release
```

## Release

1. Add release notes under a version heading in `CHANGELOG.md`.
2. Update `.release` with the matching tag, such as `v0.1.0`.
3. Merge the change to `main`.

The workflow creates a release branch, tags the commit, publishes the GitHub release, and pushes the NuGet package when trusted publishing is configured.
