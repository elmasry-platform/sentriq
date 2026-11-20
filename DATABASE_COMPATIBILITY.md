# SENTRIQ database compatibility contract

This is a Supabase/PostgreSQL implementation for the shared SENTRIQ platform and its HSE module. The active schema is delivered through four ordered migrations: `202611190001_sentriq_hse.sql`, `202611190002_commercial_entitlements_rbac.sql`, `202611190003_security_remediation.sql`, and `202611200001_database_stabilization.sql`. No migration has been applied to a hosted project.

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
| Platform Owner | Cross-company platform and tenant operations; sole authority to create, reactivate, deactivate, or manage Subowners. |
| Platform Subowner | Cross-company operational authority; cannot create/reactivate/deactivate/manage any Subowner or deactivate itself. |
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

No hosted Supabase project is linked, no deployment workflow or record was found in this repository, and no hosted/production database was modified. Do not merge or deploy based solely on local checks. Before production use, implement and security-review the trusted application server and UI adapter; configure real domains/storage; rehearse backup/restore and data migration; and review operational pricing, payment, email, monitoring, and incident procedures.
