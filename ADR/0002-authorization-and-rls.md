# ADR 0002: Authorization and PostgreSQL RLS

| Field | Value |
|---|---|
| Status | APPROVED as direction by Mohamed, 2026-11-26 (Telegram 23418049). Items under 'Acceptance tests before production' and the MFA requirement are NOT implemented. |
| Decision date | 2026-11-20 |
| Scope | Authorization responsibility and database identity context; no authorization behavior is changed by this ADR. |

## Context and evidence

The migrations already separate company management levels from functional roles. `private.can_access_hse` applies active membership, active tenant, HSE module entitlement, functional permission, and required scope. `private.has_hse_permission` considers direct permissions and role assignments, including tenant/site/org-unit/task bindings. RLS is enabled and forced on all 39 application tables. The `api` views use `security_invoker=true`. Database constraints bind HSE child records and access scopes to the same tenant.

Local pgTAP and negative tests show that the database is currently the final row boundary. The audit baseline F-01 demonstrated that a management lifecycle policy was too broad: row-level tenant isolation alone cannot ensure that the invitation state machine was used. The follow-up migration removes the direct membership write path; Laravel actor provenance, an `AccessResolver`, and production request paths have not been implemented or verified.

## Models considered

| Model | Advantages | Risks and limits |
|---|---|---|
| PHP `AccessResolver` only | Central application code; easy to express route/action checks and response behavior. | Cannot protect direct REST/database paths, future modules, or alternate clients. Every query path must reliably call it. It cannot replace database tenant isolation. |
| Database authorization only | One source for SQL/RLS, API, and background queries; robust against an omitted Laravel check when identity context is trustworthy. | UI errors can be less clear; business workflows may become hard to orchestrate; direct DB identity setup is sensitive; complicated policies require database expertise. |
| PHP `AccessResolver` + PostgreSQL RLS + database invariants | PHP provides early route/action checks and useful errors; RLS contains tenant/row access; constraints and triggers enforce immutable identity, relationship, and workflow rules. | Needs disciplined parity tests and a precise trust model so PHP and SQL do not drift. This is the recommended model. |

## Proposed decision and ownership

Adopt **PHP plus PostgreSQL RLS and database invariants**.

| Concern | Owner | Rule |
|---|---|---|
| Authentication | Supabase Auth, validated by Laravel | A signed, unexpired, verified user identity is the source of the actor UUID. Laravel session state may wrap this identity but cannot invent an actor. |
| Request/action authorization | Laravel `AccessResolver` | Use it for route, action, and UI decisions and for clear denial responses. It must consume the canonical permission/role/entitlement vocabulary and never make a positive UI decision the sole data security check. |
| Tenant and record isolation | PostgreSQL RLS | Every tenant table stays RLS-enabled and forced. User-scoped queries use a non-bypass role and the verified request identity. Tenant IDs supplied by the client are filters, not authority. |
| Effective permission and entitlement | Database authorization helpers and RLS | Module/feature status, membership state, functional permission, and scope are checked at the database boundary. Copilot needs both entitlement and `hse.copilot.use`. |
| Cross-row invariants and HSE workflow | Constraints, triggers, narrow RPCs | Composite tenant foreign keys, immutable audit/history, review-stage checks, revision checks, and privileged lifecycle transitions remain database-enforced. |
| Platform administration | Owner-gated SECURITY DEFINER RPCs | Only `api.manage_subowner` may change the Subowner roster and it checks platform Owner identity. Function ACLs remain explicit; no general-purpose `SECURITY DEFINER` endpoint is exposed. |
| Trusted server operations | Dedicated backend/service identities | Invitation, metering, and invoice jobs use narrow service paths. Keep service credentials server-side; separate the authenticated actor from the job identity in audit. |
| Background jobs | Dedicated job identity and explicit actor/tenant inputs from trusted queue payloads | Validate that a queued actor and tenant still exist and remain authorized when the job executes; write auditable job identity and initiator separately. |

For user data requests, prefer the Supabase/PostgREST path with the user's verified JWT. If Laravel connects directly to PostgreSQL, use a non-superuser, non-`BYPASSRLS` login and a transaction-scoped identity setup based only on already verified server-side claims. Use `SET LOCAL`/transaction-local settings and clear state on rollback/commit to prevent pooled-connection leakage. PostgreSQL custom GUCs are not protected credentials: a database client with access to that connection can set them. Never accept identity GUC values or actor UUIDs from browser payloads.

Service-role and postgres sessions bypass RLS. Use them only for workflows that require them, keep their credentials on the server, and validate tenant, actor, and resource relationships in the RPC. `current_user` inside a SECURITY DEFINER function is its owner and must not be treated as the original caller. In particular, bootstrap's current ACL is the protection; the function's `current_user='postgres'` expression is not caller authentication.

## Avoiding PHP/SQL drift

1. Keep permission keys, functional role definitions, scope kinds, module/feature identifiers, and transitions in a versioned authorization contract.
2. Add a canonical table-driven fixture of `(actor, membership status, tenant status, module/feature, permission, site, org unit, task, expected result)` tuples.
3. Run each tuple through PHP `AccessResolver` and through an actual PostgreSQL query under `SET ROLE authenticated` with the corresponding identity context. Assert identical allow/deny results.
4. Include negative pairs: same role/wrong tenant, allowed site/wrong org unit, assigned task/wrong site, missing functional permission, revoked grant, suspended membership, and feature entitlement without parent module.
5. Test CRUD and API views, not only helper return values. A helper returning false is not proof that every table policy uses it correctly.
6. Run these parity tests in CI against the supported PostgreSQL/Supabase image and fail on migration drift. Add a second test layer against PostgREST for JWT claim propagation and view behavior.
7. Treat any policy/function change as requiring a matching PHP vector change or a documented reason it has no PHP equivalent.

## Consequences

Laravel owns request ergonomics and orchestration, but PostgreSQL remains the final row boundary. Database constraints protect relationships and immutable workflow facts even when a caller reaches the database without the expected UI. The chosen model reuses the current Supabase Auth/RLS shape and supports future Operations data under the same tenant boundary, with separate permission keys and module entitlements. The F-01 table-write bypass is closed in the follow-up database branch; the application still must bind service-role actor UUIDs to verified identities before relying on the invitation state machine in production.

## Approved: team visibility for company Admins

Admin sees only Employee-level members; level comes from member_role only. Source: Mohamed, message 22633562 (relayed by Main). Status: APPROVED by Mohamed, 2026-11-26 (Telegram 23418049). Implemented by migration 054 (PR #15), applied to TEST on 2026-11-26.

## Log

- 2026-11-26: migrations 051, 052 and 053 were applied to TEST in one transaction, then 054 (company Admin sees only Employee-level members) in its own transaction. 052 is a no-op on TEST data (0 snapshots). Production is not changed.
