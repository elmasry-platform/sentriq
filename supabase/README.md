# SENTRIQ database

This repository contains the Supabase/PostgreSQL implementation. Migrations are forward-only except for the narrowly authorized syntax-only correction to migration 001 on this still-unmerged branch. Migration 001 establishes tenancy and HSE; `202611190002_commercial_entitlements_rbac.sql` adds normalized commercial entitlements and RBAC; `202611190003_security_remediation.sql` tightens scope and commercial security; `202611200001_database_stabilization.sql` adds subscription, grant, invitation, membership-reactivation, usage, and invoice lifecycle/concurrency corrections.

## Local development

Use a disposable local Supabase stack only:

```powershell
supabase start
supabase db reset --local
supabase test db --local
./scripts/test_database_concurrency.ps1
supabase db lint --local --fail-on error
```

GitHub Actions performs an empty-database reset, runs the complete pgTAP suite and the independent concurrency harness, and stops the stack even if an earlier step fails. Never use `supabase db push` or link a hosted project for this task.

## Authority and authorization

- Platform Owner and Subowner are separate from company memberships. Both have cross-company operational access; only Owner can create, reactivate, deactivate, or manage Subowners. A Subowner cannot deactivate itself.
- `iam.memberships.member_role` is the management level (`company_superadmin`, `company_admin`, or `employee`). Functional roles live in `iam.roles`, `iam.role_permissions`, and `iam.membership_roles`; a membership may have multiple functional roles. Functional roles cannot confer management or platform authority.
- Role permissions are reusable definitions. Site and organization-unit bindings belong to the membership-role assignment in `iam.membership_role_sites` and `iam.membership_role_org_units`. These bindings do not replace independent member `iam.site_access` and `iam.org_unit_access` grants. A task assignment cannot bypass site or organization-unit restrictions.
- Company Superadmin manages users and business role/scope assignments only within its active tenant. Company Admin and Employee cannot expand membership, permission, role, or scope access.
- HSE access requires an active tenant and membership, effective HSE entitlement, a business permission, and applicable site/org-unit/task scopes. Scope expiry/revocation and membership reactivation cleanup take effect synchronously.
- HSE and Copilot are separate commercial entitlements. `api.can_use_feature(...)` requires active HSE and feature entitlement, applicable membership, required permission, and scope. Platform operator access does not bypass feature licensing. `api.list_my_entitlements(tenant_id)` returns only the Company Superadmin's effective module/feature status for its tenant, without prices.

## Commercial operations

The seed contains an unpriced draft `hse_base` plan template for HSE without Copilot. It grants no access until explicitly priced and published. `api.create_subscription(...)` snapshots the approved price and currency. Only active/trialing subscriptions with active plans and current subscription/item periods authorize use; no past-due grace period is assumed. Past-due/suspended records do not occupy the single live-subscription slot. Canceled/expired statuses are terminal.

Platform operators issue and transition grants with `api.issue_entitlement_grant(...)`, `api.set_entitlement_grant_status(...)`, and `api.revoke_entitlement_grant(...)`. Grants use half-open time windows and can target a tenant or one exact membership. Grant commercial terms cannot be changed after issue. Billable grants require an applicable payer, currency, and explicit minor-unit rate; no production prices are seeded.

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

Migration 001's existing `private.can_access_hse()` entitlement predicate was missing two closing parentheses, causing SQLSTATE `42601`. The task authorizes this syntax-only repair because the branch is unmerged and no hosted project/deployment record exists; no other part of migration 001 was redesigned. The exact local chain now applies all four migrations from empty, all 197 pgTAP assertions pass, local SQL lint reports no schema errors, and the concurrency harness passes quota, idempotency, billing, and invitation races. GitHub Actions [run 44636378060](https://github.com/elmasry-platform/sentriq/actions/runs/44636378060) passed both jobs on implementation commit `7c7aa00e389a0ea4a981415052e43c8de8b2264a`; the database job applied all migrations, passed pgTAP and concurrency checks, then stopped the stack. No hosted/production database was modified.
