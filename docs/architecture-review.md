# WolfAuth Architecture Review

## Current Shape

WolfAuth is split into focused packages:

- `WolfAuth` owns contracts, registry, authentication subject resolution, effective access expansion, evaluation, administration, provisioning, caching, and store interfaces.
- `WolfAuth.AspNetCore` owns host integration: dependency injection, current-subject access, authorization policy encoding, ASP.NET Core authorization handlers, JSON key serialization, middleware, and administration endpoints.
- `WolfAuth.EntityFrameworkCore` owns durable persistence for subjects, assignments, and audit records.
- `WolfAuth.OpenIdConnect` and `WolfAuth.Microsoft.EntraId` own provider-specific provisioning mappers.

The core runtime keeps behavior behind interfaces (`IWolfAuthEvaluator`, `IWolfAuthEffectiveAccessResolver`, `IWolfAuthSubjectResolver`, store contracts, administration/provisioning contracts, and ASP.NET Core endpoint handlers). Static classes are limited to idiomatic ASP.NET Core extension methods.

## Decisions Validated

- Authentication binding is separated from authorization evaluation. Subject resolution maps claims into a `WolfAuthSubject`, and authorization operates on that contract.
- Authorization decisions are based on effective access snapshots, which makes direct, role, external-group, default, and bootstrap grants visible and testable.
- Administration endpoints now delegate to `IWolfAuthAdminEndpointHandler`, keeping route mapping thin and replaceable.
- WolfAuth key types are serialized as JSON strings in ASP.NET Core hosts, which keeps admin API payloads ergonomic and avoids leaking value-object internals.
- Unit and integration coverage now enforce more than 99% line and branch coverage. The current suite reaches 100% line and branch coverage for the production assemblies.

## Risks And Follow-Ups

- The in-memory persistence store is suitable for tests, samples, and local development only. Production hosts should use the EF Core store or a host-specific store implementation.
- The sample authentication handler is intentionally development-only. Production hosts should bind WolfAuth to their real OpenID Connect, Microsoft Entra ID, or platform authentication pipeline.
- The authorization registry is currently configured in code. Future iterations can add discovery/export tooling if product teams need catalog review workflows.
- Admin endpoints are intentionally minimal. Future iterations should add endpoint authorization policies, OpenAPI metadata, and operational audit queries before production exposure.

## Sample Validation

The sample API exercises the expected host flow:

- Authenticate a request as a development subject.
- Resolve the current subject from ASP.NET Core claims.
- Evaluate a protected endpoint through WolfAuth authorization policy handlers.
- Inspect effective access through a real endpoint.
- Mount the WolfAuth administration API under `/security/wolfauth`.
