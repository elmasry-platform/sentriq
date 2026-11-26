# ADR 0003: Evidence Storage and Scope Boundaries

| Field | Value |
|---|---|
| Status | PROPOSED — AWAITING OWNER APPROVAL |
| Decision date | 2026-11-20 |
| Scope | HSE evidence and authorization scope model; no storage integration is changed by this ADR. |

## Current database design

The migration creates a private `sentriq-hse-evidence` Supabase Storage bucket. Object names follow `{tenant UUID}/{site UUID}/{object name}`. Storage SELECT and INSERT policies join the object key to `hse.evidence_files`, check that the first two path segments match the row's tenant/site IDs, and require an allowed evidence status and HSE evidence permission. The metadata trigger validates that the linked inspection/finding/action/follow-up exists in the same tenant and site. Authenticated users have no object UPDATE/DELETE policy; application hard deletes are revoked.

The local negative probe verified that a Company A Superadmin cannot read Company B evidence metadata or a Company B `storage.objects` row by its exact UUID/key. It did not call the Storage HTTP API, generate a signed URL, upload bytes, or test URL expiry after authorization revocation. Hosted Storage behavior remains unverified.

## Proposed storage decision

Use **Supabase Storage for initial HSE evidence**, provided the application retains a user JWT or requests short-lived URLs only after a server-side authorization check. It aligns with the current `auth.uid()`-based database and Storage RLS and avoids creating a second storage authorization system before Laravel exists.

Keep the bucket private. Generate unpredictable object names and do not treat path prefixes as authorization. Create a metadata row only after validating the parent HSE record and permitted upload scope; confirm the object after upload; serve downloads only through Storage RLS or short-lived signed URLs issued after authorization. Keep signing credentials server-only. Define cleanup for pending/rejected uploads and retention for referenced evidence before enabling deletion workflows.

Choose S3-compatible storage later if customer residency, retention, lifecycle, malware scanning, throughput, or portability requirements justify it. A move to S3 needs a server-side authorization endpoint, narrowly scoped IAM/signing credentials, private bucket policy, short-lived signed URLs, metadata consistency, object lifecycle/retention controls, audit events, and migration/rollback plan. S3 key layout alone must never grant access.

Signed URLs are bearer capabilities for their configured lifetime. Permission changes generally do not invalidate an already issued URL, so keep expiries short, avoid logging URLs, and decide whether sensitive cases require proxy downloads or a revocable token service. Test this behavior against the selected provider before production.

## Proposed strict scope decision

For HSE records, authorize the intersection of:

```text
active identity
  ∩ active membership in active tenant
  ∩ active HSE module entitlement
  ∩ required functional permission
  ∩ active site access
  ∩ matching organizational-unit binding when present/required
  ∩ active assignment for task-scoped operations
```

Specific rules:

- A task assignment cannot create a permission. The member still needs the required functional permission and a site scope for the target site.
- The assignment's tenant, site, and organizational unit must match the task record; composite foreign keys and trigger validation bind these identifiers.
- An organizational-unit role requires active organization access and a role binding to that exact unit. Site permission does not expand into a different unit.
- A tenant-scoped role still requires explicit active site access for a site-specific record.
- Revoked/expired role assignments, scope bindings, site access, org access, task assignments, or module/feature grants deny access immediately. Re-activating a suspended membership (same member role) restores what the suspension itself took away, using a snapshot taken at suspension (migration 050; changes the earlier "reset by design" rule, pending Reviewer sign-off on PR 13). Only rows that were live and unchanged at suspension come back. Rows revoked, expired, changed, added, or whose role, role version or source delegation is no longer valid stay down, so reactivation never grants more than the member held. Ended, invited, or role-changed reactivations still start from a clean slate. Delegation envelopes are NOT restored by a member reactivation: the envelope guard forbids suspended to active outside the company-level restore, and the delegated assignments that the suspension cascade already revoked have no restore path (open decision, see PR 13). An invitation re-accept of a suspended member (api.accept_invitation) goes through the same trigger, so it restores too when the invited level equals the old member_role.
- Every future Operations record must use the same tenant/parent-key strategy while defining its own module/permission keys. HSE permissions must not imply Operations access.

The existing pgTAP suite tests matching/mismatching site and org-unit scope, task assignment mismatch, unassigned tasks, revoked bindings, and membership reactivation. The review adds exact cross-tenant child reads. Before HSE end-to-end release, add API-level tests for each list/detail/download route and ensure no Laravel query can fetch a task by ID without RLS applying.

## Session, SSO and billing timing

- Keep initial authentication with Supabase Auth as proposed in ADR 0001. Add enterprise SSO only after collecting the first customers' IdP and provisioning requirements; ensure SSO-created identities map to the existing `auth.users` IDs and membership workflow.
- Enforce MFA/step-up for platform operators and sensitive platform grant actions before inviting real customer users. No AAL/MFA check appears in these migrations.
- Keep billing provider integration out of the HSE authorization core. The database has internal subscription, grant, usage, invoice, and payment records but no payment-provider adapter or webhook verification. Integrate a provider only after selecting payment markets, invoice/tax requirements, retries, refunds, and reconciliation policy. A signed/idempotent webhook service should update the trusted billing model; browser callbacks must never grant entitlements.

## Acceptance tests before production

1. Test direct UUID list/detail and denied cross-tenant writes as `authenticated` through PostgREST.
2. Upload/read by an authorized member; deny another tenant, unauthorized site, wrong org unit, unassigned task, revoked user, and missing evidence permission.
3. Confirm storage object key, metadata tenant/site/parent, and file bytes stay consistent; test pending/rejected state and orphan cleanup.
4. Issue a signed URL, revoke membership/scope, and document whether the URL remains usable until expiry; enforce the approved expiry/serving approach.
5. Repeat the same permission/scope vectors for future Operations records.

## References

- [Supabase Storage access control](https://supabase.com/docs/guides/storage/security/access-control)
- [Supabase Storage downloads and signed URLs](https://supabase.com/docs/guides/storage/serving/downloads)
- [PostgreSQL row security policies](https://www.postgresql.org/docs/15/ddl-rowsecurity.html)
