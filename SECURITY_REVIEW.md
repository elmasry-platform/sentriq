# SENTRIQ Independent Database Security Review

| Field | Value |
|---|---|
| Review branch | `codex/security-review-adr` |
| Reviewed implementation commit | `c8019cb2e73b4615ca05f24c91a18e510fe69d72` |
| Base | `main` at `b5a16e42ecabe1b4d7b1c16c46b2442bb3870efd` |
| Review date | 2026-11-20 |

**Verdict:** **Do not approve for merge or production until F-01 is closed.** The review found no Critical or High severity finding, but ordinary tenant authorization can bypass invitation acceptance and activate a membership directly. Two lower-severity findings affect entitlement semantics and test repeatability. No remediation was applied.

## Scope and method

Reviewed the complete four-file migration chain, Supabase configuration, pgTAP suite, concurrency harness, table policies and grants, views, triggers, storage policies, function bodies and ACLs, and the current entitlement, invitation, audit, usage, billing, role, scope, and HSE workflow logic. Created and ran the isolated probe at `scripts/security_review_probes.ps1` on a separate review branch.

The checkout was clean before the probe was added. `git fetch origin` confirmed that the feature branch remained at `c8019cb2e73b4615ca05f24c91a18e510fe69d72`, `main` remained at `b5a16e42ecabe1b4d7b1c16c46b2442bb3870efd`, and the feature branch was six commits ahead and zero behind. The review branch started at the verified feature commit. No hosted Supabase project was linked (`supabase/.temp/project-ref` was absent); Supabase CLI commands targeted the local stack. No `supabase db push`, hosted connection, merge, deployment, UI repository change, or schema change was made.

The local stack was reset from an empty database and applied all four migrations. It reported PostgreSQL 15.20. The local `authenticated` role was used with `SET ROLE` for RLS probes; fixtures were created by the local postgres test connection inside a transaction and rolled back. The concurrency harness instead connects as postgres and sets a `service_role` JWT claim, so its results establish RPC behavior under that claim, not the SQL role's execute ACL or RLS behavior.

## Architecture map

```text
User authenticates with Supabase Auth
        │ signed access token (JWT)
        ▼
PostgREST request / future Laravel token validation
        │ auth.uid(), auth.role(), request claims
        ▼
api schema views (security_invoker=true)
        │ caller's PostgreSQL role and RLS remain in force
        ▼
core / iam / hse / audit tables
        │ forced RLS + private authorization helpers
        ├─ active membership + active tenant
        ├─ module entitlement + feature entitlement where required
        ├─ functional permission + site/org/task scope
        └─ workflow triggers + composite tenant foreign keys
        ▼
storage.objects private bucket policy joins evidence metadata
```

Trust boundaries:

1. Supabase Auth issues the signed identity token. PostgreSQL trusts claims provided by the Supabase request gateway; the database does not validate a bearer token itself when a caller sets request GUCs over a direct SQL connection.
2. `authenticated` requests are expected to retain their user claims and RLS. `service_role`, `postgres`, and `supabase_admin` bypass RLS or have broader authority and must stay inside trusted infrastructure.
3. `SECURITY DEFINER` functions run with their owner’s authority. All 47 `api`/`private` definer functions are owned by `postgres` and set an empty `search_path`; every one denies `PUBLIC` and `anon`. Sensitive invite and billing functions are service-role-only. Authenticated API functions perform explicit operator, membership, tenant, or permission checks. `private` is not listed as a PostgREST-exposed schema.
4. Service-only RPCs take actor/user UUID parameters. The database validates the referenced actor or user where implemented, but cannot establish that an HTTP caller authenticated as that UUID when the caller is the trusted service role. Laravel must derive these values from a validated identity and never accept them as browser authority.
5. Supabase Storage authorization is a separate API boundary. The migration defines a private bucket and object RLS policy tied to an evidence metadata row, tenant UUID, site UUID, evidence state, and HSE permission. This review exercised the local `storage.objects` RLS row query, not Supabase's signed upload/download HTTP flows.

### Schema and data-object inventory

| Schema | Tables and responsibility |
|---|---|
| `core` — 16 tables | `tenants`, `tenant_domains`, `org_units`, `sites`, `modules`, `tenant_entitlements`; plans/features/plan entitlements; subscriptions/items; entitlement grants; usage events; invoices/items; payments. |
| `iam` — 13 tables | `platform_operators`, `memberships`, `invitations`, permission catalog, roles/role permissions, direct permissions, membership-role assignments and their site/org-unit bindings, site/org-unit access, and task assignments. |
| `hse` — 9 tables | Form templates/versions, inspections/reviews, findings, corrective actions/action updates/follow-ups, and evidence metadata. |
| `audit` — 1 table | Append-only `events` ledger. |
| `api` | Twelve `security_invoker=true` read views for workspaces, sites, memberships, forms, inspections/reviews, findings/actions/follow-ups/updates, evidence, and audit events. No materialized views were found. |
| `private` | Authorization, trigger, audit, lifecycle, and entitlement helpers. Not configured as a PostgREST-exposed schema. |
| `extensions` | `pgcrypto` functions used for token hashing/random values and UUID helpers. |

The 39 application tables have 39 primary-key constraints, 39 unique constraints, 115 foreign-key constraints, and 103 check constraints in the local PostgreSQL catalog. Tenant IDs are included in important membership/site/role/task/HSE composite foreign keys. UUID primary keys use `extensions.gen_random_uuid()`; `audit.events.id` uses the sole application identity sequence (`audit.events_id_seq`). No application materialized view or configured default-privilege row was found. Existing definer functions explicitly revoke default `PUBLIC` access; the absence of default-privilege hardening for future functions is recorded as P-05.

Supabase dependencies are `auth.users` and `auth.uid()`/`auth.role()` claims, `storage.buckets`/`storage.objects`, PostgREST view options, and managed `anon`, `authenticated`, and `service_role` roles. Local extensions also include `pgcrypto`, `pg_stat_statements`, `plpgsql`, `supabase_vault`, and `uuid-ossp`.

## Findings

### F-01 — Authenticated company managers can activate memberships without invite acceptance

**Severity:** Medium — confirmed
**Affected objects:** `iam.memberships`; policies `membership_insert` and `membership_update` in `supabase/migrations/202611190002_commercial_entitlements_rbac.sql`; service-only `api.create_invitation` and `api.accept_invitation` in `supabase/migrations/202611200001_database_stabilization.sql`.

**Evidence:** `scripts/security_review_probes.ps1` runs actual DML with `SET ROLE authenticated` as an active Company Superadmin. It confirms `DIRECT_MEMBERSHIP_INSERT=active`, `DIRECT_INVITATION_BYPASS_ACTIVATION=active`, then switches the test JWT subject to the uninvited identity and confirms `UNINVITED_USER_TENANT_ACCESS=1`. The transaction rolls back. `membership_insert` permits a company manager to insert `company_admin` or `employee` rows with `status='active'`; `membership_update` permits status changes for any membership in that tenant. In contrast, `api.accept_invitation` verifies a confirmed Auth email against a hashed, unexpired, unrevoked token, locks the invitation for one-use acceptance, and emits an acceptance audit event.

**Preconditions and impact:** An authenticated Company Superadmin must know the UUID of an existing Auth user or target an existing invited membership. The manager can attach that identity to the tenant or activate its invited row without the target proving control of the matching verified email. The new identity immediately passes tenant membership RLS. HSE features still depend on module entitlement and functional scope, but the manager can then assign the normal tenant permissions/scopes. This defeats the invitation’s mailbox-verification and acceptance boundary and leaves no `invitation.accepted` record for that activation path.

**Recommended remediation:** Revoke browser-role `INSERT` on `iam.memberships`; restrict updates to safe profile fields and prevent direct changes to `status`, `member_role`, and `email`. Route provisioning and status transitions through a narrowly scoped server-side RPC. Keep invitation acceptance as the only path that makes invited identities active, and verify the Laravel caller against the Supabase Auth token before passing actor/user IDs. Add regression tests for insert, invited→active, suspended→active, and email/role changes using `SET ROLE authenticated`.

### F-02 — Membership-scoped module grants are accepted but never authorize a module

**Severity:** Low — confirmed behavior mismatch
**Affected objects:** `api.issue_entitlement_grant` and `private.has_module_entitlement` in `supabase/migrations/202611200001_database_stabilization.sql`.

The grant RPC accepts `p_membership_id` for a module grant and validates that the membership belongs to the tenant. The final module evaluator only counts module grants where `g.membership_id IS NULL`, and its signature has no membership argument. The isolated probe has a platform Owner issue a member-scoped HSE module grant through the authenticated API; the RPC accepts it while `api.list_my_entitlements` reports the HSE module as not entitled for the target Superadmin. A membership-scoped HSE module grant therefore has no effect for that member. This does not leak access to other members; it can silently fail to grant the requested access.

**Recommended remediation:** Before merge, choose and document one contract: reject membership-scoped module grants and allow member scoping only for features, or make module evaluation explicitly membership-aware and preserve the HSE module prerequisite for that member. Add positive and negative tests for both scopes. No behavior was changed in this review.

### F-03 — The concurrency harness leaves fixtures that break repeat pgTAP runs

**Severity:** Low — confirmed test hygiene defect
**Affected file:** `scripts/test_database_concurrency.ps1`.

The harness inserts a synthetic tenant, membership, usage, invoice, invoice item, and accepted invitation without cleanup. After a successful harness run, a second`npx supabase test db --local` failed four exact-count assertions (193/197 passed): owner/subowner tenant and invoice-item counts.`npx supabase db reset --local` restored the empty baseline; pgTAP then passed 197/197. The harness passed again after that clean pgTAP run. The current GitHub workflow starts a disposable database for each job and stops it in an `always()` step, so this specifically affects repeated local runs and any future shared-database job.

**Recommended remediation:** Make the harness use an isolated temporary database/branch or transactionally clean up its synthetic rows in dependency order. Add a repeatability acceptance check that runs pgTAP twice with the intended order. This review did not edit the existing harness.

## Potential security and integration concerns

### P-01 — Service-side actor UUID provenance is an application security obligation

`api.create_invitation` accepts `p_actor_user_id`; `api.accept_invitation` accepts `p_auth_user_id`. Their ACLs restrict execution to `service_role`, and their bodies validate a live Superadmin or verified matching Auth email. That prevents ordinary PostgREST authenticated callers from invoking them directly. Once Laravel exists, it must derive the UUID from a verified Supabase JWT and must not forward a caller-provided actor ID. No Laravel/backend exists in this repository, so this boundary remains unverified and is a pre-production blocker.

### P-02 — Bootstrap's `current_user` predicate does not identify its invoker

`private.bootstrap_platform_owner(uuid)` is `SECURITY DEFINER`, owned by `postgres`, and tests `current_user='postgres'`. Inside a SECURITY DEFINER function, `current_user` is the function owner; that check does not prove who invoked it. Current ACLs revoke execution from `PUBLIC`, `anon`, `authenticated`, and `service_role`, so ordinary callers cannot use it. Keep bootstrap as an explicit postgres-owned installation operation and treat its ACL as the security boundary; do not rely on that predicate if ACLs change.

### P-03 — Privileged platform operations have no database MFA/AAL check

No migration checks JWT `aal`/MFA claims before platform-owner or subowner functions. Hosted Supabase Auth policy and Laravel middleware were not available to inspect. Require and verify MFA/step-up for platform operator accounts in the deployed identity and application configuration before production; keep tenant-wide grant and operator lifecycle actions behind that policy.

### P-04 — Scheduled subscriptions reserve the live slot before their start date

`api.create_subscription` inserts `status='active'` even when `p_starts_at` is in the future. Entitlement evaluation correctly denies early access, while the unique live-subscription index includes `active` rows and can reserve the tenant's slot. Confirm whether scheduled future subscriptions are supported; if they are, model their lifecycle so an unstarted subscription cannot unintentionally block current billing setup. This is a product/lifecycle concern, not a demonstrated authorization bypass.

### P-05 — Future SECURITY DEFINER functions rely on per-function ACL discipline

The catalog has no `pg_default_acl` entry for the application schemas. PostgreSQL's default function EXECUTE behavior therefore remains in force for newly created functions unless each migration revokes it. All 47 current SECURITY DEFINER functions explicitly deny `PUBLIC` and `anon`, so this is a migration guardrail gap, not an existing public function exposure.

**Recommended remediation:** Set default function privileges for the migration owner in `api` and `private` to revoke EXECUTE from `PUBLIC`, `anon`, `authenticated`, and `service_role`, then grant the intended role per endpoint. Add a catalog assertion in CI for every SECURITY DEFINER function and its exact role ACL.

## Architecture and control review

### Authority hierarchy

| Actor | Effective boundary in reviewed code | Evidence and remaining limitation |
|---|---|---|
| Platform Owner | Platform-wide access; only role that manages Subowners; cannot deactivate self through the management RPC. | pgTAP Subowner lifecycle cases and RLS checks. Bootstrap remains an out-of-band postgres operation. |
| Platform Subowner | Platform-wide tenant and commercial authority, including entitlement grants; cannot create, reactivate, or deactivate Subowners. | pgTAP cases cover tenant-wide data and RPC denials. Uses platform operator MFA policy that is not enforced in these migrations. |
| Company Superadmin | Tenant-only management; HSE permission shortcut still requires an active HSE module entitlement. Cannot read internal plans/prices or manage platform operators. | pgTAP tests Company B isolation and pricing confidentiality; the isolated probe confirms Subowner RPC and direct operator-row insert are denied. F-01 qualifies membership lifecycle. |
| Company Admin | No tenant-management grant/revoke authority; functional roles only; no internal commercial data. | pgTAP tests role, scope, management-level, and price denials. |
| Employee | Active tenant membership plus permission, module/feature entitlement where required, and intersecting site/org/task scope. | pgTAP and isolated cross-tenant probes; exact DB/API contexts documented in `VERIFICATION_MATRIX.md`. |

Company roles cannot mutate platform operator rows through table grants. `api.manage_subowner` checks `private.is_platform_owner`; the database test suite covers create/reactivate/deactivate and Subowner denials. Company Admin cannot grant/revoke functional roles or site scopes. Suspended memberships fail authorization checks; reactivation revokes prior roles, permissions, site/org access, and task assignments.

### Tenant isolation and schema integrity

The 39 application tables across `core`, `iam`, `hse`, and `audit` have both RLS enabled and forced. No final `FOR ALL` policies remain. API views inspected are `security_invoker=true`; the API schema is PostgREST-exposed and `private` is not. Composite foreign keys bind membership, site, role, task, inspection, finding, action, and evidence references to their tenant. An authenticated Company A Superadmin could not read Company B tenant/site rows or direct-UUID HSE children, update a Company B site, insert a Company B site, delete a Company B site, read an evidence metadata row, or read its storage object.

The local probe tests concrete child rows for inspections, findings, corrective actions, action updates, and follow-ups, plus evidence metadata and `storage.objects`. It does not exercise every child-table write policy, every invalid composite-FK tuple, or the network Storage API. Treat those unexecuted cases as gaps rather than assuming the probe covered them.

### SECURITY DEFINER inventory and grants

Catalog inspection found 47 `SECURITY DEFINER` functions in `api` and `private`. All are owned by `postgres`, all have `search_path=""`, and none is executable by `PUBLIC` or `anon`.

| Function group | Functions | EXECUTE grants to `authenticated` | EXECUTE grants to `service_role` | Purpose / check |
|---|---|---|---|---|
| Authenticated API functions (13) | `api.can_use_feature`, `api.create_subscription`, `api.create_tenant`, `api.issue_entitlement_grant`, `api.list_my_entitlements`, `api.manage_subowner`, `api.publish_plan`, `api.revoke_entitlement_grant`, `api.revoke_invitation`, `api.set_entitlement_grant_status`, `api.set_feature_enabled`, `api.set_module_enabled`, `api.update_subscription_status` | Yes | No | Each checks platform operator/owner, active company Superadmin, tenant authority, or invitation tenant scope as appropriate. |
| Service-only API functions (5) | `api.accept_invitation`, `api.create_invitation`, `api.create_invoice_draft`, `api.invoice_usage_event`, `api.record_feature_usage` | No | Yes | Trusted server/billing/invitation flows; caller UUID provenance remains P-01. |
| RLS decision helpers (8) | `private.can_access_core`, `private.can_access_hse`, `private.can_access_tenant`, `private.can_manage_tenant`, `private.can_review_hse`, `private.current_membership_id`, `private.is_platform_operator`, `private.is_platform_owner` | Yes | No | Return decisions based on `auth.uid()` and active membership/operator state; schema is not PostgREST-exposed. |
| Trigger-only / owner-only functions (21) | `private.apply_inspection_review`, `private.audit_row_change`, `private.bootstrap_platform_owner`, `private.guard_action_update`, `private.guard_functional_role_permissions`, `private.guard_inspection_insert`, `private.guard_inspection_update`, `private.guard_membership_role_change`, `private.guard_operator_membership_separation`, `private.has_feature_entitlement`, `private.has_hse_permission`, `private.has_module_entitlement`, `private.record_action_status`, `private.reset_membership_authorizations_on_reactivation`, `private.validate_evidence_link`, `private.validate_member_task_permission`, `private.validate_membership_role`, `private.validate_membership_role_scope`, `private.validate_role_permission_scope`, `private.validate_subscription_item`, `private.validate_task_assignment` | No | No | Trigger execution is by the database; entitlement helpers remain private. The three groups total 47 functions. |

Catalog ACL results are the authority for exact function signatures and grants. `SECURITY DEFINER` calls do not inherit caller table RLS; each endpoint's explicit checks and its narrow ACL are therefore important. Bootstrap's `current_user` predicate is discussed in P-02.

### Entitlements, billing, invitation and audit

- HSE module access requires an active tenant, enabled module, and effective company-level module grant or active/trialing subscription item in its half-open effective period. Suspended, canceled, past-due, revoked, expired, future, disabled, or retired-plan cases are covered by pgTAP.
- Copilot requires the HSE module, an active feature grant/subscription, an active member, and `hse.copilot.use` with applicable scope. Membership feature grants do not leak to other members or tenants. Internal prices, plans, rates, invoices, usage, and payments are hidden from company roles.
- Billing treatment is constrained to `tenant_billable`, `complimentary`, or `platform_absorbed`; immutable usage records snapshot price/quota treatment. Concurrent quota checks, exact retries, conflicting idempotency payloads, and invoice line duplication were exercised.
- Invitation tokens are SHA-256 hashed, returned through service-only RPC, and accepted only once for verified matching email. Concurrency produces one winner. F-01 is a separate direct-table path around this otherwise sound RPC.
- Audit events and business history are append-only for application roles. The diff trigger uses an allowlist of field names rather than recording arbitrary text/token payloads. pgTAP confirms no authenticated delete and rejects audit mutation. Hosted audit retention and backend actor attribution remain unverified.

### HSE workflow and evidence

Inspection triggers constrain creation, submission, reviewer stage order, return/approval, revision freshness, and editable fields. Review history is immutable. Action updates have a status guard and audit trail. Existing pgTAP tests exercise stage mismatch, stale review, return, final approval, and unauthorized permissions. Composite FKs tie HSE children to the parent tenant/site. Evidence metadata must match a linked inspection/finding/action/follow-up and the evidence storage policy requires tenant/site path agreement plus evidence and HSE permission. Signed-URL expiry and revocation behavior were not tested.

## Merge and production blockers

### Merge blockers

1. Close F-01 with a forward-only migration and add negative authenticated-role tests proving direct membership insertion and privileged status transitions are denied while the invitation flow still succeeds.
2. Resolve F-02's module-grant contract or reject unsupported member-scoped module grants, with explicit acceptance tests.
3. Approve or revise the proposed identity and authorization ADRs before Laravel starts implementing its access context.
4. Close F-03 or guarantee a clean local database before every repeat test run; the checked-in CI currently uses an isolated stack per job, but local verification is not repeatable without reset.

### Production blockers

1. Implement F-01; do not expose the service-role key to a browser or client.
2. Demonstrate Laravel derives `p_actor_user_id`/`p_auth_user_id` from a validated Supabase JWT, not client fields.
3. Configure and verify mandatory MFA/step-up for platform operators; define account/session revocation and recovery.
4. Exercise real authenticated PostgREST and Storage API flows against a hosted-like Supabase environment without using customer data; verify signed object access, permission revocation, and direct UUID requests.
5. Resolve which role/connection Laravel uses. A `postgres` or `service_role` database session bypasses RLS. For direct SQL, identity GUCs must be transaction-local and set only from a verified token by trusted server code; GUC values are not cryptographically protected from a SQL client that can set them.
6. Close F-03 so CI and developer verification are repeatable.

This report does not declare the database production-ready.
