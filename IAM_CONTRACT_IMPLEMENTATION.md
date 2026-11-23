# IAM contract implementation status

Work in progress. Do not merge or deploy.

## Base and scope

Based on isolation branch e25e71e. All prior migrations stay unchanged. New migrations are forward-only. AWS and Cloudflare changes are not part of this branch. The owner separately approved applying the reviewed permissions migrations to recovera test project only. Nothing has been applied there yet.

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

Local PostgreSQL 15.20 with pgTAP, real database roles and a minimal Auth/Storage SQL harness. All ordered migrations apply from empty application schemas. Five test files execute without SQL failures or not-ok output: 242 + 26 + 30 + 14 + 51 = 363 assertions. Three repeat runs and the exact SQL ACL catalog checks pass locally. The ACL locale mismatch was corrected with deterministic collation and set equality. CI then reached the final lint step. Shared trigger lint errors were corrected in migration018; the latest CI result still must be checked. Multi-site/org tests found and fixed a legacy scope guard reading mutable permissions instead of the assigned immutable version, in migration019.

This harness is not a running Supabase Auth, PostgREST or Storage service. It does not prove HTTP routes, actual JWT verification, signed storage URLs, backend or frontend integration. GitHub CI and independent review remain required. No claim of full acceptance or production readiness is made.

## Pending owner decisions

The recommendations are recorded as inactive candidates. They do not silently change effective authority:

- Optional per-company scope for Subowners.
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
