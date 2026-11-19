# SENTRIQ database

This repository stores the Supabase/PostgreSQL implementation. Migrations are forward-only. The first migration established tenancy and HSE; `202611190002_commercial_entitlements_rbac.sql` adds the normalized commercial and authorization model without rewriting the first migration.

## Local development

Run against a disposable local Supabase stack only:

```powershell
supabase start
supabase db reset --local
supabase test db --local
```

The GitHub Actions workflow performs the same empty-database migration and database test sequence. Never use `supabase db push` or a linked project for this repository's current implementation work.

## Authority and authorization

- Platform Owner and Subowner are separate from company memberships. Both can operate across companies; only Owner can create/reactivate/deactivate Subowners.
- `iam.memberships.member_role` stays the single company management level (`company_superadmin`, `company_admin`, or `employee`). Functional roles live in `iam.roles`, `iam.role_permissions`, and `iam.membership_roles`; one membership can hold multiple functional roles.
- Company Superadmin manages only its tenant's users and business role/scope assignments. Functional roles cannot grant management or platform authority.
- Effective HSE access requires an active tenant, membership, HSE entitlement, business permission, and applicable site/org-unit/task scopes. Site and org-unit access intersect with assigned tasks. Organization-unit scope is exact; descendants do not inherit automatically.
- `api.can_use_feature(tenant_id, feature_key, permission_key, site_id)` is the feature gate for sensitive operations such as Copilot. An HSE module entitlement never grants `hse.copilot` by itself. Platform operators' operational access does not satisfy this commercial feature check. `api.list_my_entitlements(tenant_id)` returns only the caller's effective module/feature booleans; subscription prices, other members' grants, usage, invoices, and payments remain platform-only.

## Commercial operations

`core.features` separates features from modules. The seed includes an unpriced draft `hse_base` plan template with HSE and no Copilot; it grants no access until a priced version is explicitly published. Plans are versioned; `api.publish_plan(...)` requires explicit prices and entitlement rows. `api.create_subscription(...)` requires a valid active plan plus an explicit price snapshot for each plan item. Only `active` and `trialing` subscriptions in their effective period authorize use; no past-due grace period is assumed.

Platform operators can issue/revoke grants with `api.issue_entitlement_grant(...)` and `api.revoke_entitlement_grant(...)`. Grants use half-open time windows and can target exactly one tenant or membership. Billable grants require a payer tenant, currency, and approved minor-unit rate; no prices are seeded. The Copilot grant path can be membership-scoped and cannot bypass the HSE module entitlement.

The trusted server must check the feature gate before model execution, then call the service-role-only `api.record_feature_usage(...)` with measured quantity and an idempotency key. That RPC derives configured rates and quota, rejects prompt/response content, and deduplicates usage. `api.create_invoice_draft(...)` and `api.invoice_usage_event(...)` are trusted service-role functions; the usage-event unique index prevents invoicing an event twice. The `core.payments` ledger is provider-neutral; no payment gateway, tax rules, collection, or card-data handling is implemented.

## Invitations and audit

Company Superadmins can call `api.create_invitation(...)` for Company Admin or Employee accounts. It returns a raw random token once while storing only its SHA-256 hash. The recipient must accept with a verified matching Supabase Auth email using `api.accept_invitation(token)`. Email delivery/resend is not integrated. Invitations cannot create Superadmins or platform operators.

Audit diffs include allowlisted operational fields only. Emails, display names, tokens, passwords, prompts/responses, evidence bytes, and other sensitive payloads are excluded. Audit events and business history are append-only. Ordinary authenticated hard deletes are revoked; use status, revocation, or archival transitions.

## Provisioning and compatibility

Create the first platform owner after their Auth account exists by running `private.bootstrap_platform_owner(auth_user_uuid)` as the local database operator (`postgres`). `api.create_tenant(...)` provisions a company and its initial Superadmin but does not enable HSE or another paid module. Grant access by an explicit plan/subscription or platform entitlement.

Existing `core.tenant_entitlements` rows are not modified or discarded. Migration `202611190002` copies them to module-level grants with the original tenant, module, active/suspended status, validity end, actor, and creation time. Since the old switch had no price/billing data, those rows are marked complimentary during transition; no monetary terms are inferred. The legacy table becomes read-only for authenticated users, and `legacy_entitlement_id` makes the backfill traceable and idempotent. No Copilot grant is backfilled. New `api.v_memberships` retains the existing UI `role` field as the management level and appends `membershipLevel` and `functionalRoles` fields.

The current UI remains mock/local: its dashboard reads `data/mock-data.json`, and `LocalFormRepository` uses browser `localStorage`. No live Supabase adapter or Copilot server exists in the UI repository. Keep `private` unexposed, keep service-role credentials on a trusted server, and treat IDs/tenant claims from the browser as untrusted input.

## Verification status

`supabase/tests/database/entitlements_rbac.test.sql` covers HSE-versus-Copilot licensing, membership-scoped grant isolation and expiry, role union/non-escalation, cross-tenant role rejection, task/site and org-unit intersections, review approval/return, tenant RLS, role management denial, and delete/audit protections. Run the commands above before merging. This migration has not been applied to a hosted project.
