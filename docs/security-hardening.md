# Security Hardening

Date: 2026-10-07

## Security Defaults

WolfAuth keeps authorization decisions server-side. Frontends may use effective access to hide or disable UI, but backend enforcement remains mandatory.

Recommended defaults:

- Keep `RequireKnownSubject = true` for internal products.
- Register every permission and role in the host registry.
- Validate assignments before persistence.
- Grant bootstrap administrators only through explicit configuration.
- Keep external groups as inputs to internal role mappings, not as direct product authority.
- Audit administrative assignment changes and sensitive authorization decisions.

## Threat Model

Primary risks:

- A valid external identity receives product access without internal provisioning.
- A malformed assignment grants an unknown or unintended permission.
- External groups are treated as full product roles without host-controlled mapping.
- Bootstrap administrator configuration is too broad.
- The frontend is trusted as the authorization source.
- Effective access caches outlive assignment changes.

Mitigations in the current implementation:

- Known-subject enforcement is enabled by default.
- `WolfAuthAssignmentValidator` checks target shape and registry references.
- External group grants must be mapped as WolfAuth assignments.
- Bootstrap administrator rules match explicit subject id, provider plus external id, or email.
- ASP.NET Core handlers call the server-side evaluator.
- Administration operations invalidate effective access caches.
- `WolfAuthAuditingEvaluator` records authorization decisions when enabled.

## Operational Guidance

Hosts should:

- Keep permission keys stable and descriptive.
- Treat role and permission assignment changes as privileged operations.
- Protect `MapWolfAuthAdminApi(...)` behind administrator permissions before exposing it broadly.
- Review bootstrap administrator configuration during deployment.
- Use durable audit storage for production systems.
- Prefer short cache lifetimes for sensitive applications.
