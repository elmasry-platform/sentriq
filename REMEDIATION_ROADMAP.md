# SENTRIQ Remediation Roadmap

This roadmap is advisory. No schema or product behavior was changed during the independent review.

## P0 — Critical security or integrity blockers

No Critical finding was confirmed in the reviewed local implementation.

## P1 — Required before backend development or merge

### P1-01 Close direct membership activation bypass (F-01)

- **Objects/files:** `iam.memberships`; `membership_insert`/`membership_update` policies in `supabase/migrations/202611190002_commercial_entitlements_rbac.sql`; `api.accept_invitation` in `supabase/migrations/202611200001_database_stabilization.sql`; new forward migration and database tests.
- **Recommended change:** Remove authenticated direct insert. Restrict authenticated updates to profile fields; status, management level, and identity/email transitions must go through a narrow lifecycle API. Preserve owner-controlled Superadmin management and invitation acceptance as the only ordinary onboarding activation path.
- **Dependencies:** Decide whether company Superadmins may change an already-active employee's email or level, and how suspended/ended memberships are reinstated. Do not rely on RLS alone if column grants still allow lifecycle writes.
- **Required tests:** Under actual `authenticated` role deny new active/invited membership insert, invited→active, suspended→active, direct role escalation, and email reassignment. Verify the correct verified invite can activate the intended `company_admin`/`employee`; wrong/unverified/replayed tokens fail; owner-managed Superadmin creation remains separate.
- **Acceptance criteria:** Only verified invitation acceptance activates ordinary users; no client table write can bypass the state machine; all transitions emit auditable actor and invitation evidence; all pgTAP and negative probe cases pass.

### P1-02 Resolve module-grant scope semantics (F-02)

- **Objects/files:** `api.issue_entitlement_grant`, `private.has_module_entitlement`, `private.has_feature_entitlement` in `supabase/migrations/202611200001_database_stabilization.sql`; product entitlement contract.
- **Recommended change:** Either reject non-null `p_membership_id` when `p_module_key` is set, or make module entitlement evaluation membership-aware and ensure a member-specific module still never activates the module for other members.
- **Dependencies:** Product owner confirms whether modules can be sold/granted to one member or only to a tenant.
- **Required tests:** Tenant-level module active/inactive; member-level grant activates only the selected member if supported; other member remains denied; revoked/expired/suspended grants deny immediately; feature grants remain behind the module gate.
- **Acceptance criteria:** RPC validation and authorization evaluator implement one documented contract with positive and negative scope tests.

### P1-03 Approve identity and authorization decisions before Laravel integration

- **Objects/files:** `ADR/0001-identity-and-authentication.md`; `ADR/0002-authorization-and-rls.md`; current `auth.uid()`/`auth.role()` use and `SECURITY DEFINER` API functions.
- **Recommended change:** Approve Supabase Auth as initial identity source and define exact Laravel token/session and user-scoped database path. Reject client-supplied actor UUIDs. Decide whether Laravel uses PostgREST with the user JWT or a constrained direct-DB connection with transaction-local claims.
- **Dependencies:** Owner decision, Laravel framework/version, Supabase Auth project configuration, and deployment topology.
- **Required tests:** Invalid signature/issuer/audience/expiry, wrong subject, role switching, transaction rollback/pool reuse, disabled user/membership, and service-role isolation. Assert user requests never use `postgres` or `service_role` database authority.
- **Acceptance criteria:** Signed identity provenance documented and tested end-to-end; service credentials unavailable to browser; authorization parity suite is part of CI.

### P1-04 Protect platform operator accounts with MFA/step-up

- **Objects/files:** Supabase Auth configuration and Laravel authorization middleware for `api.manage_subowner`, entitlement grant/revoke, module/feature switches, plan/subscription updates.
- **Recommended change:** Require MFA for Owner and Subowner sign-in, and a verified step-up/AAL claim for sensitive platform operations. Define recovery and break-glass access.
- **Dependencies:** Hosted Supabase Auth project, chosen recovery policy, and application session design.
- **Required tests:** Operator without MFA/required AAL cannot execute high-impact operations through Laravel/API; valid step-up succeeds; recovery cannot silently disable the second factor.
- **Acceptance criteria:** Hosted configuration and API enforcement are verified and audit records distinguish the operator and action. Current migrations do not enforce AAL.

### P1-05 Make database verification repeatable (F-03)

- **Objects/files:** `scripts/test_database_concurrency.ps1`; `.github/workflows/database.yml`; database test instructions.
- **Recommended change:** Run concurrency in a disposable isolated database/branch, or capture and remove every synthetic row in dependency order. Ensure failure paths also clean up.
- **Dependencies:** Supabase CLI branch/database lifecycle and CI runner setup.
- **Required tests:** Run reset, pgTAP, concurrency, pgTAP again; run concurrency twice; confirm no synthetic rows survive and all runs pass.
- **Acceptance criteria:** Repeated local and CI verification is deterministic from documented order and produces no cross-run data contamination.

### P1-06 Pin service actor provenance

- **Objects/files:** Laravel controllers/jobs calling `api.create_invitation`, `api.accept_invitation`, `api.record_feature_usage`, and invoice RPCs.
- **Recommended change:** Derive user and membership IDs from verified server context; resolve current tenant membership server-side; reject arbitrary actor IDs in user-facing DTOs. For background jobs, record a job identity and initiating actor separately.
- **Dependencies:** P1-03 identity decision and Laravel implementation.
- **Required tests:** Tampered actor, tenant, membership, and invitation user IDs are rejected; valid signed actor reaches only own tenant; service-only RPC ACL remains narrow.
- **Acceptance criteria:** No request payload can select the audit actor or identity being invited/accepted; audit actor has verifiable provenance.

### P1-07 Harden default function privileges

- **Objects/files:** PostgreSQL default privileges for the migration owner in `api` and `private`; `.github/workflows/database.yml`; a catalog assertion in database verification.
- **Recommended change:** Revoke default EXECUTE from `PUBLIC`, `anon`, `authenticated`, and `service_role` for future functions in exposed/sensitive schemas. Grant the intended role explicitly per RPC.
- **Dependencies:** Confirm migration role/owner in CI and hosted deployments so `ALTER DEFAULT PRIVILEGES` applies to the actual object creator.
- **Required tests:** Create a synthetic SECURITY DEFINER function as the migration role and assert nobody executes it until an explicit grant; assert every shipped definer has empty/fixed `search_path` and exact allowed grantees.
- **Acceptance criteria:** New privileged functions fail closed by default and CI detects ACL or search-path drift.

## P2 — Required before HSE end-to-end operation

### P2-01 Test real HSE and evidence API flows

- **Objects/files:** PostgREST `api` views, `hse` RLS, `storage.objects` policies, Laravel endpoints, `ADR/0003-storage-and-scope-boundaries.md`.
- **Recommended change:** Add end-to-end tests for direct UUID access, all HSE child reads/writes, evidence metadata, upload/download, cross-site/org/task scope, and permission revocation.
- **Dependencies:** Laravel backend and deployed-like Supabase Auth/Storage test project with synthetic data.
- **Required tests:** Authorized upload/download; cross-tenant, unauthorized-site, wrong-org, unassigned-task, suspended member, revoked permission, mismatching metadata path, and stale signed URL scenarios.
- **Acceptance criteria:** Every route and storage request returns only the authorized rows/objects; signed URL expiry matches the approved policy; no service key reaches the client.

### P2-02 Confirm scheduled subscription lifecycle

- **Objects/files:** `api.create_subscription`; `core.subscriptions`; `one_live_subscription_per_tenant` index.
- **Recommended change:** Decide whether future start dates are valid. If valid, represent scheduled status distinctly or ensure the live unique slot is reserved only when intended. If not, reject future start dates.
- **Dependencies:** Billing owner and provider/invoice lifecycle policy.
- **Required tests:** Future subscription does not grant access early and cannot unintentionally block an active subscription; one live effective subscription remains enforced; cancellation/past-due transitions behave as documented.
- **Acceptance criteria:** Effective-access and subscription-slot semantics are explicit and tested together.

### P2-03 Verify authenticated authorization parity

- **Objects/files:** Laravel `AccessResolver`, `private.has_hse_permission`, `private.can_access_hse`, `api.can_use_feature`, pgTAP and CI workflow.
- **Recommended change:** Implement the shared decision vectors in ADR 0002 and execute them through both PHP and PostgreSQL under real non-bypass roles.
- **Dependencies:** Laravel code and approved role/scope contract.
- **Required tests:** Same actor/tenant/status/module/feature/permission/site/org/task combinations in PHP, RLS, and PostgREST views.
- **Acceptance criteria:** No vector disagreement; mutations are denied even when route/UI checks are skipped.

## P3 — Later enhancements

### P3-01 Enterprise identity and SSO

- **Objects/files:** Supabase Auth configuration, identity adapter, tenant domain/SSO onboarding.
- **Recommended change:** Collect customer IdP and lifecycle requirements, then select SSO provisioning/deprovisioning behavior without changing user IDs unexpectedly.
- **Dependencies:** Customer demand and verified Option A deployment.
- **Required tests:** IdP initiated login, email/subject mapping, deprovisioning, duplicate identity, and tenant domain separation.
- **Acceptance criteria:** SSO user maps to one Auth identity and still passes the same invitation, membership, and RLS gates.

### P3-02 Storage portability decision

- **Objects/files:** Supabase Storage bucket and evidence API.
- **Recommended change:** Revisit S3-compatible storage only against actual residency, retention, scanning, throughput, and portability needs.
- **Dependencies:** HSE operating experience and customer requirements.
- **Required tests:** Migration, lifecycle retention, signing credential rotation, short-lived URL, and rollback.
- **Acceptance criteria:** Object access remains metadata- and permission-bound after any provider change.
