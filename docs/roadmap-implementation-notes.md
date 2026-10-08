# Roadmap Implementation Notes

Date: 2026-10-07

## Implemented Scope

This pass advances the multi-iteration roadmap beyond the core evaluator.

Implemented packages:

- `WolfAuth`
- `WolfAuth.AspNetCore`
- `WolfAuth.EntityFrameworkCore`
- `WolfAuth.OpenIdConnect`
- `WolfAuth.Microsoft.EntraId`

Implemented capabilities:

- ASP.NET Core dependency injection, middleware, dynamic policies, authorization handlers, attributes, and minimal admin endpoints.
- Persistence abstractions for subjects, assignments, audit records, and units of work.
- Entity Framework Core context, entities, and store implementation.
- Idempotent provisioning service for subject upserts and deactivation.
- OpenID Connect and Microsoft Entra ID claim-to-provisioning mappers.
- Administration service for assignment validation, upsert, removal, audit, and cache invalidation.
- Audit records and an evaluator decorator that records authorization decisions.
- Effective access cache and cached resolver decorator.
- Assignment validation for unknown permissions, unknown roles, invalid targets, and invalid grants.
- CI coverage for build, tests, pack, and release packaging.

## Remaining Future Work

The implementation deliberately keeps some areas at foundation level:

- Full reusable admin UI is not included yet.
- Microsoft Graph directory search is not included yet.
- Invitation workflows and email sender abstractions are not included yet.
- Distributed cache support is not included yet.
- Database migrations are not generated in this pass; hosts can integrate `WolfAuthDbContext` into their migration workflow.

## Validation

The implemented surface is covered by tests for:

- Core authorization.
- Authentication binding.
- Provisioning.
- Administration.
- Audit emission.
- Cache invalidation.
- ASP.NET Core authorization integration.
- Provider mappers.
- EF Core persistence.
