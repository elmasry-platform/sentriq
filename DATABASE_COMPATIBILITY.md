# SENTRIQ database compatibility contract

This is a Supabase/PostgreSQL implementation for the shared SENTRIQ platform and its HSE module. The ordered forward migration chain is authoritative. The 23 IAM migrations through 202611250023 were applied to the recovera test project on 23 November 2026, after CI and independent review. Later migrations require their own verification and controlled application. This is not a production-readiness claim.

## Sources and scope

- The UI reference is [`elmasry-platform/sentriq_ui`](https://github.com/elmasry-platform/sentriq_ui/tree/main), branch `main`. Its dashboard currently reads mock JSON and its form repository uses browser `localStorage`.
- The supplied V3.3.1 archive is architectural reference material, not an instruction to override the owner's authority requirements or a record of approved production migrations.
- This repository implements database schemas and RPCs only. The UI repository, a trusted Laravel/API/Edge Function server, and external providers are not changed here.

## Shared platform and HSE data model

The shared schemas cover tenants, sites, memberships, platform operators, authorization, organization units, audit, modules, features, plans, subscriptions, entitlement grants, usage, invoices, invoice lines, and payments. HSE records cover forms, immutable published form versions, inspections, reviewer history, findings, corrective actions, follow-ups, and evidence metadata. HSE evidence bytes belong in private object storage; PostgreSQL holds validated metadata and object keys. Operations and future modules can add independent domain schemas while reusing tenant, identity, authorization, audit, and entitlement primitives.

Tenant-owned rows and cross-tenant references use tenant identifiers and composite relationships where implemented. Authorization derives tenant access from the authenticated identity and active membership; a browser-provided tenant ID alone is never proof of access.

## Authority and scope intersections

| Principal | Database authority |
|---|---|
| Platform Owner | All-company read visibility through audited platform RPCs; platform management as separately granted, sole authority to manage Subowners. No new company operational write authority from the read grant. |
| Platform Subowner | All-company read visibility through audited platform RPCs; cannot create/reactivate/deactivate/manage any Subowner. No new company operational write authority from the read grant. |
| Company Superadmin | Membership and business configuration within its own active tenant; no platform/operator or internal pricing authority. |
| Company Admin | Executes explicitly granted business permissions; cannot grant permissions, scopes, roles, or management levels. |
| Employee | Assigned permissions within active tenant and applicable scopes. |

Platform operators are separate from company memberships. Membership management level (`company_superadmin`, `company_admin`, `employee`) stays separate from multiple functional roles. Functional roles define reusable permissions and cannot confer company-management or platform authority.

An HSE authorization decision requires an active tenant and membership, effective HSE entitlement, a direct or role permission, and the applicable site, organization-unit, and task checks. Role-site and role-organization-unit bindings belong to a membership-role assignment; they do not replace each membership's independent site/org-unit access. A task assignment cannot bypass those boundaries. Expired/revoked role assignments and scope bindings stop authorizing access synchronously. Organization-unit scope is exact; descendants do not inherit automatically.

## Current UI data contract

| UI concept | Database/API representation |
|---|---|
| `workspaces`, `workspaceId`, `industryLabel` | `core.tenants`; serialize UUIDs as strings and map `workspaceId` in one API adapter. |
| Sites (`id`, `name`, `code`, `city`) | `core.sites`; site references must belong to the same tenant as their parent record. |
| Users (`id`, `displayName`, `email`) | Supabase Auth identity plus SENTRIQ membership/profile; application passwords are not stored in SENTRIQ schemas. |
| `role`, `siteIds` | `role` maps to membership management level; `functionalRoles`, permissions and scopes are separate normalized fields. |
| Forms | Typed ownership/status/revision plus JSONB bilingual content and immutable published snapshots. Preserve conditions, scoring, repeat groups and field configurations. |
| Inspections | Tenant/site scoped, references the exact immutable published form version, stores answers as JSONB and workflow/revision/actor metadata as typed fields. |
| Reviews, findings, actions, follow-ups | Append-only review/action history and tenant-safe references to the inspection/form version. Reviewer stage is workflow configuration, not a global database role. |
| Evidence | Tenant-scoped metadata and private storage key; bytes remain in object storage. Validate tenant/site access for both metadata and signed object access. |
| Audit | Append-only platform or tenant event with actor, target, time, and allowlisted field diffs. Avoid secrets and unnecessary personal data. |

The UI currently uses one demo role per user; the database/API supports multiple functional roles. The adapter must preserve existing visible field shapes where needed while moving access checks to the server. Do not treat demo JSON IDs, browser filters, or UI navigation as authorization.

## Commercial access and confidentiality

HSE module access and HSE Copilot feature access are separate. Copilot requires active HSE module entitlement, active Copilot feature entitlement, a valid membership, the required functional permission, and applicable scopes. Platform-wide operational access does not bypass feature licensing.

Only Owner/Subowner can view internal plan rates, subscription snapshots, grant rates, usage billing, invoices, invoice lines, and payments. Company membership APIs expose only safe effective module/feature status for that tenant. Entitlements are evaluated synchronously against tenant, membership, module/feature, grant state and half-open dates, plan state, subscription state, and item periods. Active/trialing are the only effective subscription states. Past-due/suspended records do not hold the live subscription slot; canceled/expired records are terminal. Retired plans and globally disabled features/modules deny access.

Legacy `core.tenant_entitlements` rows and their effective state/metadata remain traceable through the migration backfill. The old switch has no verified pricing history, so no historical monetary values are inferred. New plans must be explicitly priced and published; no production prices are seeded.

## Invitations, audit and trusted server boundary

Invitation database RPCs are service-role-only. A future server must validate the bearer token through Supabase Auth, derive actor identity and verified email from that trusted response, and keep the service-role key server-side. The database stores a token hash, checks expiry/tenant/management level/email, prevents replay, and serializes acceptance and reinvitation. Invitations may create Company Admins or Employees only. Email delivery is not implemented.

Audit and business history are append-only where required. Ordinary authenticated hard deletes are revoked for memberships, role/scope assignments, commercial history, usage, invoice lines, payments, audit events, published versions, and HSE review/action history. Use status, revocation, or archival transitions.

## Supabase-specific and portable capabilities

| Capability | Dependency |
|---|---|
| Tenant tables, foreign keys, checks, partial/unique indexes, JSONB, triggers, advisory locks, transaction semantics, security-definer functions | PostgreSQL behavior; these are broadly portable, subject to PostgreSQL version and extension availability. The project targets PostgreSQL 15. |
| Auth identity and JWT context (`auth.users`, `auth.uid()`, `auth.role()`) | Supabase Auth schema/functions and request claim injection. A standalone Laravel/PostgreSQL deployment must supply an equivalent trusted identity/JWT adapter and replace these dependencies. |
| `anon`, `authenticated`, `service_role` roles and PostgREST schema exposure | Supabase role and API behavior. Do not expose the `private` schema; only the configured API-facing schemas are exposed. |
| `extensions` objects and pgTAP tests | Supabase-managed extension schema/installed extensions; another PostgreSQL installation must provision compatible extensions and roles. |
| HSE evidence storage bucket and object policies | Supabase Storage (`storage.buckets`, `storage.objects`) integration. A standalone service needs an equivalent private object store and tenant-checked signed access. |
| RPC calls through `api` schema | Supabase PostgREST behavior and grants. A Laravel adapter can call PostgreSQL functions directly only after reproducing authentication context and least-privilege transaction setup. |

This schema is therefore not a drop-in standalone Laravel database package. Porting requires an explicit Auth/JWT context, database-role and API grant design, migration for storage integration, and integration tests for the replacement server.

## Verification and rollout boundary

Historical implementation evidence records four migrations and 197 pgTAP assertions. The follow-up branch `codex/foundation-security-remediation` adds `202611200002_foundation_security_remediation.sql` and expands verification to actual PostgreSQL roles, exact function-ACL catalog checks, F-01/F-02 probes, and repeatable concurrency cleanup. Current 242-assertion results and the GitHub Actions run associated with the final implementation head are recorded in `REMEDIATION_RESULTS.md`.

The recovera test database has the reviewed IAM chain through 202611250023. No production database, frontend or backend deployment was performed as part of that application. Do not merge or deploy based solely on local checks. Before production use, implement and security-review the trusted application server and UI adapter; configure real domains/storage; rehearse backup/restore and data migration; and review operational pricing, payment, email, monitoring, and incident procedures.


## Identity boundary status and AWS port

`private.request_actor_id()` is an incremental adapter used by newer code, not a completed isolation of Supabase dependencies. Legacy routines, including `phase1_permission_allowed`, still use `auth.uid()` and `auth.role()` directly. Replacing the wrapper alone will not port authentication. Inventory and replace every Auth-schema, JWT-claim and role dependency during the AWS migration, then run the whole authorization suite plus HTTP-token and connection-pool identity-reset tests.

Several grant-time guards allow privileged offline migration/fixture work only when `session_user='postgres'` and the active role setting is `none`. Authenticated and service-role request execution must never use that bypass. The AWS adapter must connect with a dedicated least-privileged login, never the schema owner, map verified identity in a transaction, and explicitly set/reset its role and claims. These checks are Supabase-role-aware today; retain or replace their semantics deliberately. Direct SQL function calls are not automatically equivalent to PostgREST requests.

## DDL and profile publication operations

Migration 202611250001 intentionally removes the old one-Superadmin index: agreed Model A permits several Company Superadmins, tested by the two-active-Superadmins regression. Tenant/user uniqueness remains. Its table alterations and constraint validation take locks. Apply with a tested maintenance window, lock/statement timeout plan, backup and restore rehearsal, and measured tenant-sized data before first production use. The current test project was empty.

Profile versions default to `sealed=true` to fail closed. A privileged publisher must explicitly insert an unsealed draft, insert its complete contents, and seal it through the guarded application flow in the same transaction. Omitting `sealed=false` makes later content inserts fail; this is not a reason to disable sealing triggers in application code. Only disposable test fixtures may temporarily disable guards, restoring them immediately.

Keep all migrations already recorded on recovera unchanged. A pre-first-client baseline consolidation may be planned for new installations only, after comparing the resulting schema, ACLs, policies and tests with the full chain and preserving existing hosted history. Squashing a Git PR commit does not squash SQL migration versions.

## Authorization performance measurement

A PostgreSQL 15.20 local microbenchmark used 10,000 deliberately row-dependent source checks with one valid root envelope. `EXPLAIN (ANALYZE, BUFFERS)` measured 233 ms total (about 23 microseconds per source check, 70,001 shared-buffer hits). The null-source control measured 138 ms. These are isolated warm-cache microbenchmarks on tiny fixtures, not an endpoint SLA, deep-chain test, or tenant-scale load test. The full evaluator may call this helper multiple times per row, so repeated per-row evaluation can be material.

Migration 202611250024 wraps remaining bare identity calls in policy scalar subqueries, allowing identity initplans, and adds a user-id-leading memberships index. This does not cache permission decisions. Do not add a cross-request authorization cache: revocation, membership, tenant, entitlement and expiry changes must remain effective immediately. Before a real client, measure representative row counts and delegation depths with the actual list queries. If repeated chains dominate, use statement-local distinct-source evaluation/materialization with identical synchronous validity checks and negative security tests. A persistent cache is not justified by this fixture measurement.
