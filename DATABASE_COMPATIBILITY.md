# SENTRIQ database compatibility contract

This document records the requested database behavior and the data contract exposed by the current UI. An initial Supabase PostgreSQL migration is in `supabase/migrations/202611190001_sentriq_hse.sql`; it has not been deployed or verified against a hosted project.

## Scope and inspected sources

- UI: [`elmasry-platform/sentriq_ui`](https://github.com/elmasry-platform/sentriq_ui/tree/main), branch `main`.
- The dashboard service reads `data/mock-data.json`; the visible demo roles and record shapes are in `lib/sentriq/dashboard-service.ts`.
- Form authoring types and local repository behavior are in `lib/forms/domain.ts` and `lib/forms/repository.ts`.
- The local checkout for this task is `elmasry-platform/sentriq`, separate from the UI repository.
- The supplied V3.3.1 archive describes a proposed Supabase/PostgreSQL architecture and Gate A preparation. Its recommendations are reference material; they do not override the owner's requirements below or constitute approved production migrations.

## Required tenant and access model

Every company is a tenant. Every business record, including sites, forms, inspections, findings, corrective actions, follow-ups, and evidence metadata, must carry a tenant identifier. A company member can only read or change records belonging to that company and within their assigned site, organization scope, function, or task.

| Actor | Scope and authority |
|---|---|
| Platform owner (the user) | Full platform and cross-company control, including access to all tenant data and lifecycle controls. Sole actor allowed to create or deactivate subowners. |
| Subowner | Same platform-wide operational authority as the owner. Cannot create or deactivate subowners, including itself or the owner. |
| Company superadmin | One tenant only. Can manage company users and set their allowed functions, sites, visibility, and task assignments. Cannot grant authority outside its own tenant or manage platform owners. |
| Company admin | One tenant only. Gets a permission set selected by that tenant's superadmin. Can exercise those permissions but cannot change user permissions, roles, or access grants. |
| Employee | One tenant only. Gets only the functions, sites, records, and tasks assigned by the tenant superadmin. |

Enforce these rules in the database/API authorization layer, not only by hiding UI navigation. The platform owner and subowner are platform-level principals, not tenant memberships. Company superadmins/admins/employees use tenant memberships. Tenant role grants must not be able to create platform-level access.

The V3.3.1 proposal gives platform admins global platform capabilities but explicitly withholds tenant data reads. That conflicts with the owner's cross-company access requirement. Before using that design, change its platform authorization rule and test owner/subowner access and the owner-only subowner lifecycle boundary. Do not silently map `platform_admin` to the owner requirement.

The migration implements a separate platform operator table for `owner` and `subowner`, and gives the two operators cross-tenant access. Only the owner can add or deactivate a subowner. Platform operators create companies and designate the initial company superadmin. The tenant-domain registry is operator-only; a verified domain is metadata and does not itself grant data access.

## UI data contract to persist

| UI concept / field shape | Database representation |
|---|---|
| `workspaces` (UI name for companies), `industryLabel` | `core.tenants` (or equivalent company table), with stable ID, name, industry, status, timestamps. |
| `sites`: `id`, `name`, `code`, `city` | `core.sites`, tenant-scoped with a unique `(tenant_id, code)`. Validate that every linked site belongs to the same tenant as the record. |
| `users`: `id`, `displayName`, `email` | Identity-provider user plus SENTRIQ principal/profile; do not store passwords in the application schema. |
| `workspaceId`, `siteIds`, `role` | Tenant membership, scoped role/permission assignments, site grants, and optional organization scope. Prefer permission keys and scope rows over hard-coded UI role checks. |
| Forms: bilingual title/help, sections, questions, validation, config, conditions, scoring | Form definition plus immutable published-version snapshots. Preserve the UI's nested JSON structures (JSONB is suitable for config/snapshots); keep identity, tenant, status, revision, and ownership as typed columns. |
| Inspections: `templateId`, `templateVersion`, `siteId`, `inspectorId`, `status`, `currentStage`, `answers`, `revision`, timestamps | Tenant/site-scoped inspection instance referencing a specific immutable form version. Answers can be JSONB keyed by stable question IDs. Keep workflow status, revision, actor, and timestamps typed and auditable. |
| Review history: stage, decision, actor, reason, revision | Append-only inspection review/transition records. The stage names in the demo (`reviewer_1`, `reviewer_2`, `final_reviewer`) are workflow configuration, not global database roles. |
| Findings: inspection/question link, priority, status | Tenant-scoped finding rows with a same-tenant inspection reference. `question_id` points into the inspection's immutable form-version snapshot. |
| Actions: finding/inspection link, owner, priority, status, due dates, revision | Tenant/site-scoped corrective-action rows; owner must be an active member of that tenant. Track status changes in append-only history. |
| Follow-ups: action, owner, due date, status, outcome | Child records of corrective actions, carrying tenant scope (directly or through a protected composite relationship). |
| Evidence: filename, MIME type, byte size, status, linked record, uploader | File metadata table with tenant scope and storage object key. Store file bytes in object storage, not PostgreSQL. Enforce tenant checks on both metadata and signed file access. |
| Audit events: actor, action, record type/ID, summary, time | Append-only audit table with tenant/platform scope, actor identity, target, and timestamp. Avoid storing tokens or unnecessary personal data in summaries. |

The UI's demo types use `workspaceId`; the database/API may call this `tenant_id`, but the adapter must map the naming consistently. IDs in the JSON demo are strings; database UUIDs are suitable if the API serializes them as strings. Preserve ISO-8601 timestamps and the listed status values at the API boundary or translate them in a single adapter.

## HSE-first modules and future ERP modules

Build the shared identity, tenant, site, authorization, audit, and module-entitlement layer once. Put HSE-specific records under an HSE module boundary (forms, published versions, inspections, reviews, findings, corrective actions, follow-ups, evidence metadata). Future Operations or other modules can add their own tables without turning the shared identity model into HSE-only tables.

`core.modules`/tenant entitlements (or equivalent) should allow the platform owner to enable modules per company. Within HSE, company superadmins should assign granular capabilities such as form design, inspection execution, review stages, corrective-action ownership, closure review, and read-only audit access. The demo's ten roles are useful UI presets, but must not be the only authorization mechanism because the requirement is to configure function access per employee.

The initial migration creates shared `core`, `iam`, `audit`, `api`, and `private` schemas and HSE tables for forms and published snapshots, inspections and review history, findings, corrective actions and updates, follow-ups, and evidence metadata. `api.v_*` views expose workspace aliases and camel-case fields for a UI adapter. The UI still needs a live Supabase client adapter; today it uses static/local demo data.

## Compatibility gaps to close before a production migration

1. The migration has not been applied to a Supabase project. It needs migration execution and security review before production use.
2. The current dashboard's `getDashboard(workspaceId)` accepts an arbitrary workspace ID and filters mock data in application code. Replace it with authenticated API reads whose tenant scope is derived from the verified principal; never trust a browser-supplied tenant ID as authorization.
3. The UI currently models one role per user plus `siteIds`; the requested admin-configurable access needs multiple permission/scope assignments and task assignments. Keep a compatibility adapter while the UI evolves.
4. The demo has no explicit form version object in the dashboard `Inspection` type beyond `templateVersion`, while the form domain has published snapshots. The API must guarantee inspections retain the exact published snapshot they used.
5. The demo includes tenant-less audit entries and evidence linked by a polymorphic record type/ID. Production data must always have an explicit tenant or platform scope and must validate polymorphic references before accepting writes.
6. Owner/subowner lifecycle control is not represented in the demo role model and differs from the supplied archive's platform-admin data-access restriction.
7. Provision the first owner after creating their Auth account by running the operator-only `private.bootstrap_platform_owner(auth_user_uuid)` function. Then call `api.create_tenant(name, industry_label, first_company_superadmin_auth_user_uuid)` as a platform operator.
8. Verify tenant domain ownership outside the database before setting a domain row to `verified`. Keep the `sentriq-hse-evidence` Storage bucket private and use object paths `tenant_uuid/site_uuid/file_name`.
9. Employee invitation email delivery is not included yet. A user must first have a Supabase Auth account; the company superadmin can then add that Auth user as a company membership.

## Acceptance checks for database/API rollout

- Requests from a company member cannot read or write another company's tenant, site, HSE, or evidence data, even when IDs are guessed or tenant IDs are changed in the request.
- A company superadmin can configure company members' functions, scope, and assignments; a company admin and employee cannot modify those grants.
- A company admin cannot gain capabilities that were not explicitly granted by its company superadmin.
- Owner and subowner can manage all tenants and tenant data; only the owner can create/deactivate subowners. A subowner cannot change this rule through database/API calls.
- Inspection records retain an immutable form version; review transitions, findings, action updates, and closure decisions preserve actor and time history.
- Site and task assignment restrictions are applied on every read and write, not only in dashboard filtering.

