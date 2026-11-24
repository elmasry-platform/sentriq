# SENTRIQ database

This repository contains the Supabase/PostgreSQL implementation. Migrations are forward-only except for the narrowly authorized syntax-only correction to migration 001 on this still-unmerged branch. Migration 001 establishes tenancy and HSE; `202611190002_commercial_entitlements_rbac.sql` adds normalized commercial entitlements and RBAC; `202611190003_security_remediation.sql` tightens scope and commercial security; `202611200001_database_stabilization.sql` adds subscription, grant, invitation, membership-reactivation, usage, and invoice lifecycle/concurrency corrections; `202611200002_foundation_security_remediation.sql` closes direct membership writes, enforces tenant-level modules, and hardens future function ACL defaults.

## Local development

Use a disposable local Supabase stack only:

```powershell
supabase start
supabase db reset --local
supabase test db --local
./scripts/test_database_concurrency.ps1
./scripts/verify_database_concurrency_failure_cleanup.ps1
./scripts/security_review_probes.ps1
./scripts/security_catalog_checks.ps1
supabase db lint --local --fail-on error
```

GitHub Actions performs static contract checks, an empty-database reset, pgTAP, security probes, catalog ACL verification, normal and injected-failure concurrency checks with cleanup, two more pgTAP runs without reset, lint, and stops the stack even if an earlier step fails. Never use `supabase db push` or link a hosted project for this task.

## Authority and authorization

- Platform Owner and Subowner are separate from company memberships. Both have cross-company operational access; only Owner can create, reactivate, deactivate, or manage Subowners. A Subowner cannot deactivate itself.
- `iam.memberships.member_role` is the management level (`company_superadmin`, `company_admin`, or `employee`). Functional roles live in `iam.roles`, `iam.role_permissions`, and `iam.membership_roles`; a membership may have multiple functional roles. Functional roles cannot confer management or platform authority.
- Role permissions are reusable definitions. Site and organization-unit bindings belong to the membership-role assignment in `iam.membership_role_sites` and `iam.membership_role_org_units`. These bindings do not replace independent member `iam.site_access` and `iam.org_unit_access` grants. A task assignment cannot bypass site or organization-unit restrictions.
- Company Superadmin manages invitations and business role/scope assignments only within its active tenant. Direct membership table writes are revoked for `anon`, `authenticated`, and `service_role`; verified invitation acceptance is the ordinary activation path. A narrow `service_role` RPC can suspend or end an existing membership but cannot activate it or change identity, tenant, email, or management level. Company Admin and Employee cannot expand membership, permission, role, or scope access.
- HSE access requires an active tenant and membership, effective HSE entitlement, a business permission, and applicable site/org-unit/task scopes. Scope expiry/revocation and membership reactivation cleanup take effect synchronously.
- HSE and Copilot are separate commercial entitlements. `api.can_use_feature(...)` requires active HSE and feature entitlement, applicable membership, required permission, and scope. Platform operator access does not bypass feature licensing. `api.list_my_entitlements(tenant_id)` returns only the Company Superadmin's effective module/feature status for its tenant, without prices.

## Commercial operations

The seed contains an unpriced draft `hse_base` plan template for HSE without Copilot. It grants no access until explicitly priced and published. `api.create_subscription(...)` snapshots the approved price and currency. Only active/trialing subscriptions with active plans and current subscription/item periods authorize use; no past-due grace period is assumed. Past-due/suspended records do not occupy the single live-subscription slot. Canceled/expired statuses are terminal.

Platform operators issue and transition grants with `api.issue_entitlement_grant(...)`, `api.set_entitlement_grant_status(...)`, and `api.revoke_entitlement_grant(...)`. Grants use half-open time windows and can target a tenant or one exact membership. Grant commercial terms cannot be changed after issue. Billable grants require an applicable payer, currency, and explicit minor-unit rate; no production prices are seeded.

Module grants are tenant-scoped. Membership-specific exceptions apply only to feature grants and require the parent company module. The migration aborts with IDs if it finds historical membership-scoped module grants; review those records explicitly before applying the migration.

A trusted server must check feature entitlement before model execution, then call service-role-only `api.record_feature_usage(...)` with measured quantity and an idempotency key. The RPC rejects prompt/response content, globally deduplicates keys, rejects a different payload on reuse, returns the original event for an exact retry even after quota exhaustion, and serializes quota consumption. Billing rates and quota are snapshotted from the grant/subscription. `api.create_invoice_draft(...)` and `api.invoice_usage_event(...)` are trusted service-role functions; concurrent retries return one invoice line and increment totals once. `core.payments` is provider-neutral. No gateway, tax, collection, card data, or pricing policy is implemented.

## Invitations and audit

Invitation creation/acceptance RPCs are executable only by `service_role`. A future Edge Function or Laravel/API server must validate the caller bearer token with Supabase Auth, derive identity and verified email from that trusted response, then invoke the RPC with server-only credentials. Never accept an actor UUID from browser JSON or expose the service-role key to a browser. The database stores a token hash, checks expiry/email/tenant/level, prevents replay, and serializes acceptance and reinvitation. Invitations may create Company Admins or Employees only. Email delivery is not integrated.

Audit diffs contain allowlisted operational fields; emails, tokens, passwords, prompts/responses, evidence bytes, and unnecessary personal data are excluded. Audit events and business history are append-only. Ordinary authenticated hard deletes are revoked where history must be retained; use status, revocation, or archival transitions.

## Provisioning and UI compatibility

Bootstrap the first platform Owner after its Auth account exists by calling `private.bootstrap_platform_owner(auth_user_uuid)` as local database operator (`postgres`). `api.create_tenant(...)` creates a company and initial Superadmin but does not turn on a paid module. Enable access only through an explicit plan/subscription or platform grant.

Legacy `core.tenant_entitlements` rows are retained and backfilled to module grants with their tenant, module, effective status, validity, actor, and creation time. The old records have no verified historical billing information; migration metadata preserves traceability without inventing monetary values. No Copilot grant is backfilled. The membership view preserves the existing UI `role` field as management level and adds `membershipLevel` and `functionalRoles`.

The UI still reads mock/local data (`data/mock-data.json` and browser `localStorage`); there is no live Supabase adapter or trusted Copilot server. IDs and tenant claims from the browser are untrusted. Keep schema `private` unexposed, and keep service-role credentials on a trusted server.

## Supabase dependency and verification boundary

Core relational behavior (constraints, RLS, indexes, triggers, transaction locks, JSONB, and functions) uses PostgreSQL capabilities targeting PostgreSQL 15. Identity and JWT context (`auth.users`, `auth.uid()`, `auth.role()`), Supabase database roles (`anon`, `authenticated`, `service_role`), PostgREST schema exposure, managed extensions, and `storage.buckets`/`storage.objects` are Supabase-specific. A standalone Laravel/PostgreSQL deployment needs an explicit Auth/JWT adapter, equivalent database roles/grants and request context, compatible extensions, and a private object-storage integration; this schema is not a drop-in standalone Laravel package.

Migration 001's existing `private.can_access_hse()` entitlement predicate was missing two closing parentheses, causing SQLSTATE `42601`. The authorized syntax-only repair is retained in the historical migration. Follow-up branch `codex/foundation-security-remediation` adds the forward-only migration `202611200002_foundation_security_remediation.sql`; its test sequence and CI run are recorded in repository-root `REMEDIATION_RESULTS.md`. No hosted/production database was accessed or modified.

## Dynamic member permissions and individual entitlements (migration 040)

Three independent layers are evaluated server-side: the company subscription, individual member entitlements (`core.entitlement_grants` rows scoped to one membership and one module or feature, with `can_use`, `can_delegate`, start, optional expiry, reason, grantor and revocation) and functional permissions (Default, Allow, Deny; Deny wins).

- Company Superadmin default is every enabled catalog permission that passes the member's entitlement gate, present and future, minus explicit Deny decisions. Restrictions are Deny decisions on exact permission keys. `iam.superadmin_capability_limits` is no longer read for catalog keys; the migration converts each can_use=false limit on a catalog key into a tenant-scope Deny decision and records every limit's outcome in `iam.superadmin_limit_migration_review` (anything it cannot interpret is left for review, not converted).
- Operation A (restrict an existing company entitlement) is a personal grant with `can_use=false`. Operation B (exception outside the subscription) is a personal grant with `can_use=true`. Both go through `api.platform_set_member_entitlement` (platform power `member.entitlements`). Functional decisions go through `api.platform_set_member_decision` (`member.permissions`). Both powers follow the existing model: Owner always, Subowner until the Owner withdraws.
- Delegation: only from a live personal grant with `can_delegate=true`, to another active member of the same company, same module/feature, no longer than the source, never delegable again. Revoking the source ends delegated access. Company Superadmin status alone grants none of this.
- `api.member_effective_access(tenant, membership)` is the single server-calculated read for the UI. Each permission reports `entitlement_state` (company, personal_exception, restricted, none) and `functional_state` (deny, default_superadmin, allow, allow_scoped, inherited, none), plus lapsed history. Personal grants report live, expired, revoked or not_started.
- Invitation acceptance and delivery are out of scope for this change.

### Review hardening in 040

- Apply 040 as the `postgres` role (the migration runner). The decision triggers let `session_user = postgres` bypass their guards, and the limit data migration writes protected rows directly. Apply is a separate approval step.
- Decisions written through `api.platform_set_member_decision` (and Denies migrated from superadmin limits) carry `protected_origin`. A company Superadmin cannot clear, replace, shorten or bypass them (a `specific_override` does not lift a protected tenant Deny), and nobody can clear a Deny on their own membership.
- A Deny keeps enforcing even if the delegation envelope it came from ends. The source check applies to Allow only.
- Membership-scoped grants through the legacy `issue_entitlement_grant`, `set_entitlement_grant_status` and `revoke_entitlement_grant` RPCs now need `member.entitlements`; a personal restriction cannot be suspended, only revoked through the audited RPC.
- A delegated grant is live only while its source holder is not restricted for that module or feature; the holder cannot delegate while restricted.
- `member_effective_access` is tenant-wide. Site and org-unit people scope only narrows a request that names one, so scoped rows are flagged `scoped` and must be checked with `api.authorize`.
- Baseline: `iam_contract_boundaries` tests 73, 75-80, 85 and 96 fail identically on `main` (stale Subowner assertions) and are not caused by 040.
- Owner-of-the-decision rule: a Deny placed by a company Superadmin can be replaced or cleared only by that Superadmin, or through the platform operator RPC (Owner, or a Subowner holding `member.permissions`). Other Superadmins cannot. If the setter is suspended or removed the Deny stays in force and only the operator RPC can clear it. A `specific_override` Allow lifts such a Deny only when the override was made by the Deny's own setter (or an operator); an override by another Superadmin does not. Denies set by an active non-Superadmin delegate keep the older rule (the setter or a company Superadmin).
