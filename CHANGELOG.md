# Changelog

All notable changes to WolfAuth are documented in this file.

## [Unreleased]

No unreleased changes.

## [v1.0.0] - 2026-10-08

### Stable

- Authentication subject normalization from an authenticated `ClaimsPrincipal`.
- ASP.NET Core registration, middleware, and current-subject access for authenticated requests.
- Generic OpenID Connect claims mapping for authentication provisioning scenarios.
- Microsoft Entra ID claims and group mapping through `WolfAuth.Microsoft.EntraId`.
- Entra ID web site sample that validates sign-in, callback handling, current-subject resolution, and protected dashboard access.
- NuGet package metadata, README, package icon, XML documentation, symbols, and source package configuration for the authentication package set.

## [v0.1.0] - 2026-10-07

### Added

- Initial WolfAuth solution scaffold.
- Core authentication, authorization, provisioning, persistence, audit, and ASP.NET Core integration experiments.
- Initial CI build, test, coverage, packaging, and trusted publishing workflow.
