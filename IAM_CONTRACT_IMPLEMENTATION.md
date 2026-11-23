# IAM contract implementation status

Work in progress. Do not merge or deploy.

## Base and scope

Based on isolation branch e25e71e. All prior migrations stay unchanged. New migrations are forward-only. AWS and Cloudflare changes are not part of this branch. The owner separately approved applying the reviewed permissions migrations to recovera test project only. The reviewed migrations through023 were applied there on 23 November 2026;024 is a subsequent reviewed performance change.

## Implemented and locally exercised

- Multiple active Company Superadmins.
- Exact task binding for direct allows.
- Module-neutral catalog lookup for permission evaluation.
- Delegation provenance on direct decisions and ancestor expiry/status checks.
- Suspension and explicit Superadmin adoption of delegated decisions.
- Grantor permission/use/delegate checks.
- Tenant-only specific override semantics.
- Explicit named actions, action-level grants/denies, profile action composition.
- Role-version RLS, tenant-qualified references, immutable published content and a guarded publisher.
- Narrow platform membership suspend/reactivate RPC without operational-data access.
- Assignment-limited supervisor projection and notes-only mutation API, covered by projection/notes/unassigned/tenant-negative RPC regression tests.
- Replaceable identity entry point for new code.

## Verification so far

Local PostgreSQL 15.20 with pgTAP, real database roles and a minimal Auth/Storage SQL harness. All ordered migrations apply from empty application schemas. Five test files execute without SQL failures or not-ok output: 242 + 26 + 30 + 14 + 97 = 409 assertions. Three repeat runs and the exact SQL ACL catalog checks pass locally. The ACL locale mismatch was corrected with deterministic collation and set equality. CI then reached the final lint step. Shared trigger lint errors were corrected in migration018; the latest CI result still must be checked. Multi-site/org tests found and fixed a legacy scope guard reading mutable permissions instead of the assigned immutable version, in migration019.

This harness is not a running Supabase Auth, PostgREST or Storage service. It does not prove HTTP routes, actual JWT verification, signed storage URLs, backend or frontend integration. GitHub CI and independent review remain required. No claim of full acceptance or production readiness is made.

## Pending owner decisions

The recommendations are recorded as inactive candidates. They do not silently change effective authority:

- Subowner scope was resolved by the owner: all companies read-only via audited platform RPCs. No extra operational writes.
- Least-privilege starting profile contents for Admin/Employee.
- Invitation-time pinned profile version versus acceptance-time current default.

## Remaining work and review hotspots

- Complete action semantics across legacy and new evaluator paths. Read/write uses the dedicated decision API; named-action API rejects read/write.
- Scoped assignment tests cover independent site/org envelopes, refusal to combine them, exact source capture and revocation. Profile versions are sealed against appends. These controls still need independent review.
- Named-action adoption/revocation lifecycle needs full parity with read/write decisions.
- Supervisor projection is deliberately narrow; it returns empty work_contact until a defined tenant-owned field source exists. It does not invent HR or medical schemas.
- Same-role/different-scope assignment semantics remain constrained by the older active-role unique index.
- Invitation timing and baseline-content choices remain unresolved, not guessed.
- Full trusted backend AccessResolver and HTTP/API integration are not present in this database-only repository.
- All privileged routines and actual table/RPC/storage paths need final review; helper-only tests are not sufficient acceptance.

## Portability

Keep PostgreSQL constraints, composite references, transactions and RLS. Replace Supabase adapters, not the security model. Existing code still references auth.users, auth.uid/auth.role, API roles, PostgREST and storage.objects/buckets. New request_actor_id is a thin identity boundary, not a completed migration of every legacy dependency. A trusted AWS backend must validate tokens and establish transaction-local identity with a least-privileged database role, with separate tests for connection reuse and context reset. Export/restore, Auth identity mapping and private object-store migration must be rehearsed before first customer cutover.

## Recovera migration preflight

Remote history uses original hosted timestamp versions unlike this repository. A separate staging directory preserves the 18 recorded remote migration statements and versions, adding only the new 20261125 migrations. No remote history repair is allowed. Dry-run for001..018 succeeded. Replaying that exact remote baseline locally plus001..018 passed all355 tests three times. Migration019 and updated363-test suite must be rerun against it before applying. A fresh dry-run and exact pending list are required after final review.

## Independent review follow-up

Migrations020..022 protect assignment identity on update, require explicit profile/default provenance (old API rejects ambiguous sources), and align specific-override precedence for named actions with legacy read. Regression tests include nondelegable Superadmin version swap, concurrent profile envelopes, and narrow action restoration. Latest review required again. The user subsequently requested global platform read visibility, overriding the earlier no-operational-access rule. Migration023 implements that change via platform_list_companies and platform_read_company, with explicit table/column allowlists, bounded pagination and a same-transaction audit entry per successful call. Existing direct table and authorize mutation boundaries are unchanged. Token hashes, storage object keys, payment/usage metadata and Auth credentials are excluded. It does not imply new mutation authority.

## Backend boundary update

The user rejected a Next.js backend layer and requested a separate backend service. Backend framework selection is pending, and no server code or further server design is part of this change.

## Platform read privacy note

The user explicitly approved all-company read visibility for both Platform Owner and Sub-owner (Telegram7487759). Historical engagement before_values/after_values JSON may include personal data. These fields are visible through the audited company read RPC, so platform operators can see that history. Auth credentials and invitation token hashes remain excluded. Every successful read RPC is audited. This is an application audit record, not an independently immutable external audit ledger.

## Additional independent review

Migrations024..026 add identity policy initplans and a memberships user index, close legacy unaudited operator SELECT paths with restrictive policies, add an audited operator roster, remove inert direct invitation-write policies, prevent role-assignment lifetime edits, fail closed on null actions, and attribute global catalog reads to platform audit scope. Existing Owner-class platform mutation powers shared by Subowners are intentionally retained pending any explicit product restriction.

## Owner-controlled platform permissions

Migration028 supersedes implicit shared Subowner writes. Subowners retain all-company audited read visibility and the confirmed company suspend/reactivate default. Every other platform write requires a named permission granted by the Owner through an audited RPC. Superadmin suspension/ending, company closure and rename are Owner-only. The proposed all-writes-OFF default was not adopted; the user confirmed the lifecycle-ON default.

## Company suspension and delegated role restoration (migration 030)

Company suspension is a reversible service pause, not a permanent removal of delegated role assignments. Migration 030 extends 029: the envelope cascade marks only previously unrevoked sourced membership_roles that it takes down. Reactivation restores those same rows, including their original immutable role version and unchanged site/org-unit bindings, only for envelopes restored in that cycle. No replacement assignments are created.

The revoked-history guard has two narrow exceptions: clearing the provenance marker without changing any history, and clearing revocation metadata during the nested tenant lifecycle restore with valid provenance and a passing current-authority check. All other revoked-role mutations remain forbidden. Setting provenance requires the nested tenant suspension cascade and a marked suspended source envelope. Inserted markers and a forged transaction-local setting alone are rejected. The gate uses transaction-local iam.delegation_tenant_restore plus trigger nesting, not a credential or an API permission. No API-role ACL is added.

Restore rechecks the full source chain, role_assignment capability on every ancestor, exact tenant/employee/site/org-unit envelope scope, active target membership and matching published role family/version, role validity, current root capability and role-permission can_use/can_delegate limits, ended scope bindings, and conflicting active assignments. Independent source revocation, membership suspension/end/role change, and last-engagement end clear provenance, including when the affected person is the role recipient rather than an envelope endpoint. The existing role revocation RPC can finalize a marked takedown without changing its historical revocation metadata.

Every restored role emits iam.delegation_source.restored with restored=role_assignment, cause=tenant_reactivation, original assignment ID, envelope ID and actor. A marked role that cannot return emits iam.delegation_source.restore_skipped with a specific reason: validity_window_ended, envelope_not_restored, membership_inactive_or_changed, engagement_ended, role_not_assignable, conflicting_current_role, scope_binding_ended, capability_no_longer_allowed, outside_envelope_scope, or capability_limit_tightened. Skips clear provenance, so a later loosening of authority never silently queues a grant. The blanket 029 role_assignment_history_immutable skip is superseded, not re-emitted.

No backfill infers provenance from the old human-readable revoke_reason. Already-revoked historical rows remain revoked because that text cannot prove an exclusive cause. Migration 029 remains unchanged. This change is forward-only and does not deploy itself.
