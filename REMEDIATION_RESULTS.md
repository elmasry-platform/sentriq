# SENTRIQ Foundation Security Remediation Results

## Branch and commit record

| Item | Reference |
|---|---|
| Repository | `elmasry-platform/sentriq` |
| Source audit branch and commit | `codex/schema-coverage-audit` — `31368375fa4c4fcafd9f5a6d2078b2dc79ced854` |
| Remediation branch | `codex/foundation-security-remediation` |
| Final remediation implementation commit | `6c4ea47422f0bd7f213b0414a7073a8e3fb5b272` |
| Pull request | To `main`; link will be added after creation. No merge was performed. |

The eight existing implementation, stabilization, security-review, and schema-audit commits remain in this branch's ancestry. The source branch histories were not rewritten. `main` was not changed.

## Findings addressed

| Finding | Result |
|---|---|
| F-01 membership activation bypass | Removed `INSERT`, `UPDATE`, and `DELETE` privileges on `iam.memberships` for `anon`, `authenticated`, and `service_role`; restored authenticated `SELECT` only. Dropped `membership_insert` and `membership_update`. The new service-only `api.set_membership_status` supports suspension and ending only; it cannot activate a membership or change its tenant, user, email, or management role. The existing hashed, verified-email, expiry-checked, single-use invitation flow remains the ordinary activation path. Company Superadmins can still invite Company Admins and Employees. Company Admins and Employees cannot manage memberships. |
| F-02 entitlement scope mismatch | Added `core.entitlement_grants` constraint rejecting membership-scoped module grants and explicit `22023` rejection in `api.issue_entitlement_grant`. Company module grants and member-specific feature grants are tested. A member feature grant remains ineffective until the parent company module is enabled. The migration reports conflicting historical grant IDs and aborts without rewriting records. |
| F-03 repeatability and fixture leakage | Reworked the concurrency harness to use unique IDs, actual `service_role` SQL sessions, tracked worker jobs, and exact marker-scoped cleanup in `finally`. Cleanup follows FK order and removes only records and audit events created by that run. The harness checks that zero synthetic records remain and fails otherwise. An injected failure after fixture creation verifies that cleanup also runs on the failure path. |
| P-05 future function grants | For the `postgres` migration owner, revoke the built-in `PUBLIC` function default globally and revoke `PUBLIC`, `anon`, `authenticated`, and `service_role` defaults in `api` and `private`. CI creates temporary SECURITY DEFINER probes in both schemas and confirms new functions are not executable until explicitly granted. Catalog checks enforce owner, empty fixed `search_path`, explicit ACLs, and exact authenticated/service-role allowlists. |

`private.bootstrap_platform_owner` was not reinterpreted: its ACL remains the security boundary. Inside a SECURITY DEFINER function, `current_user` identifies its owner, not the invoker. The service RPC still cannot prove that Laravel derived its actor UUID from a verified human JWT; that P-01 obligation remains open.

## Migration and recovery

Added forward-only migration `supabase/migrations/202611200002_foundation_security_remediation.sql`. It revokes direct membership writes, installs the narrow lifecycle RPC, validates historical module-grant scope without changing rows, adds the module-scope constraint, hardens function defaults, and replaces the entitlement grant RPC with explicit module-scope validation.

The migration is transactional. If existing data contains membership-scoped module grants, its preflight raises an error listing the grant IDs and rolls back the entire migration. Review and resolve those rows through an explicitly approved business decision before retrying. No automatic rollback migration is provided: recover by applying a reviewed forward migration or restore the pre-migration database backup. The migration has only been exercised on the disposable local Supabase stack; hosted migration owner and data checks are still required before deployment.

## Regression tests and actual PostgreSQL roles

The expanded `supabase/tests/database/entitlements_rbac.test.sql` suite contains 242 assertions. Security paths run under actual `SET ROLE anon`, `SET ROLE authenticated`, and `SET ROLE service_role`; JWT claim settings are set separately where the function contract requires them. Membership table grants and policies are checked independently of RLS. SECURITY DEFINER calls are tested with the SQL role that is expected to call them. `postgres` is used only for fixture setup and privileged catalog inspection.

Coverage includes direct active membership insertion, invited-to-active and suspended-to-active writes, management-level, user, tenant, email, and profile-field mutation, cross-tenant manipulation, Company Admin/Employee denial, verified invitation acceptance, unverified/wrong-email/expired/replayed invitation denial, service lifecycle suspension/end, rejected lifecycle activation, valid tenant-level module grant, rejected membership-level module grant, member feature scope, parent-module requirement, and cross-membership feature isolation.

The pgTAP transaction temporarily grants service-role `SELECT` on `core`, `iam`, and `audit` so tests can inspect RPC effects. Those grants roll back with the test transaction and are not part of a migration or deployed schema.

## Local repeatability results

The full local sequence was run from `npx supabase db reset --local` on implementation commit `0df7a6caef3755c0d5c9c02b07de57887dd82545`. After the PowerShell wrapper's final exit-code normalization was added in `6c4ea47422f0bd7f213b0414a7073a8e3fb5b272`, the injected-failure wrapper was rerun locally and the full CI sequence passed on that commit:

1. Migration application from empty — PASS, all five migrations.
2. Static contract checks — PASS.
3. pgTAP — PASS, 242/242.
4. F-01/F-02 security probes under actual `authenticated` SQL role — PASS.
5. SECURITY DEFINER ownership, fixed path, exact ACL, membership privilege/policy, and default-function probes — PASS.
6. Concurrency harness — PASS: 12 actual service-role usage calls, quota 3 produced exactly 3 successes; exact retry and conflicting idempotency payload were checked; eight invoice retries produced one line and one amount update; concurrent invitation acceptance had one winner. Exact-run fixture and audit cleanup verification found zero remaining rows.
7. Injected failure after setup — PASS: process failed as intended and `finally` cleanup verified zero remaining fixture and audit rows.
8. pgTAP without reset — PASS, 242/242.
9. Second concurrency harness run — PASS, exact-run cleanup verified zero rows.
10. Third pgTAP run without reset — PASS, 242/242.
11. `npx supabase db lint --local --fail-on error` — PASS, no schema errors.
12. `scripts/check_database_contract.ps1` and `git diff --check` — PASS.

Local concurrency run markers from the accepted sequence: `sentriq-f03-c5e5b4aff4a249b6bb74abe82120fd51` and `sentriq-f03-a60d32366de64b23be91010d746232cf`. CI concurrency run markers on the final implementation commit: `sentriq-f03-e6180e6e99fe42c1a77fd901aade9311` and `sentriq-f03-493e14c61ee048b4ac64475a56f90152`. No concurrency fixture survived any run. The failure-injection path also verifies cleanup after partial execution.

## Changed files

- `.github/workflows/database.yml`
- `ADR/0001-identity-and-authentication.md`
- `ADR/0002-authorization-and-rls.md`
- `ARCHITECTURE_DECISIONS_REQUIRED.md`
- `DATABASE_COMPATIBILITY.md`
- `DATABASE_EVOLUTION_ROADMAP.md`
- `DOMAIN_CATALOG.md`
- `IMPLEMENTATION_REPORT.md`
- `REMEDIATION_ROADMAP.md`
- `REMEDIATION_RESULTS.md`
- `SCHEMA_COVERAGE_AUDIT.md`
- `SECURITY_REVIEW.md`
- `TARGET_DATA_MODEL.md`
- `VERIFICATION_MATRIX.md`
- `scripts/check_database_contract.ps1`
- `scripts/security_catalog_checks.ps1`
- `scripts/security_review_probes.ps1`
- `scripts/test_database_concurrency.ps1`
- `scripts/verify_database_concurrency_failure_cleanup.ps1`
- `supabase/README.md`
- `supabase/migrations/202611200002_foundation_security_remediation.sql`
- `supabase/tests/database/entitlements_rbac.test.sql`

## CI and pull request

GitHub Actions workflow: `.github/workflows/database.yml`.

- [Workflow run 44815836147](https://github.com/elmasry-platform/sentriq/actions/runs/44815836147) passed on `6c4ea47422f0bd7f213b0414a7073a8e3fb5b272`.
- Required jobs `static-contract` and `supabase-database` both passed. The database job completed the fresh reset, pgTAP, security probes, catalog ACL checks, successful and injected-failure concurrency cleanup, repeat pgTAP runs, and lint with no schema errors.
- Expected database job sequence: local stack start, empty reset, pgTAP, security probes, catalog ACL checks, successful and injected-failure concurrency cleanup, two further pgTAP runs, lint, and guaranteed local stack shutdown.
- Pull request to `main`: link will be added after creation. The PR will remain open for review and will not be merged.

## Remaining findings and integration gates

- **P-01:** Laravel is not present. A trusted backend must validate JWT issuer, signature, audience, expiry, and subject, derive actor/user UUIDs from that verified identity, and keep service credentials server-side.
- **P-02:** Bootstrap ACL is unchanged and remains the security boundary. Preserve postgres-only installation access; never treat `current_user` inside SECURITY DEFINER as caller identity.
- **P-03:** MFA/AAL step-up for Owner/Subowner and sensitive platform operations must be configured and tested in hosted Auth and application middleware.
- **P-04:** Product/billing owner must decide whether future-start subscriptions should reserve the single live-subscription slot.
- **P-05 deployment:** The local default ACL applies to migration role `postgres`. Confirm the hosted migration/object owner and apply equivalent defaults if it differs.
- Before hosted migration, inspect historical grants for module rows with non-null `membership_id`; the migration intentionally fails if any are present.
- Verify real hosted PostgREST, Storage HTTP upload/download, evidence access, signed URL expiration/revocation, and browser-to-backend authorization behavior.
- The UI still uses mock/local data; no Laravel adapter, HSE incident/risk/permit domain, hosted Auth setup, or production operational controls were added in this PR.

No hosted or production Supabase database was linked, queried, migrated, or otherwise accessed. No deploy occurred. This is not a production-readiness claim.
