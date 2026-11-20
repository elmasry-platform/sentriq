# SENTRIQ database stabilization and security implementation

## Disposition

**Database branch acceptance: PASS for review/merge.** The verified implementation commit is `7c7aa00e389a0ea4a981415052e43c8de8b2264a` on `codex/platform-entitlements-rbac`; GitHub Actions run [44636378060](https://github.com/elmasry-platform/sentriq/actions/runs/44636378060) passed both jobs. This is not a production-readiness claim. The branch has not been merged into `main` or deployed. The local checkout had no linked Supabase project, and the repository contains no database deployment workflow. No hosted or production database was modified.

## Migration summary

| Migration | Work and disposition |
|---|---|
| `202611190001_sentriq_hse.sql` | Corrected only the missing closing parentheses at the end of the `private.can_access_hse()` entitlement predicate. This is a syntax-only repair; its predicates and behavior are unchanged. The task's migration review found no evidence of deployment: the feature branch is unmerged, no remote Supabase project is linked, and no deployment workflow/record is present in this repository. The supplied request explicitly authorizes this narrow fix on this branch. |
| `202611190002_commercial_entitlements_rbac.sql` | Preserved as already implemented on this unmerged branch. It provides normalized commercial plans, subscriptions, grants, usage, invoicing, multi-role RBAC, invitations, and audit. Its ACL ordering correction from the prior implementation remains after the invoice RPC definition. |
| `202611190003_security_remediation.sql` | Preserved as already implemented on this unmerged branch. It adds effective entitlement checks, assignment-bound site/org scopes, tighter commercial RLS, invitation lifecycle handling, and security/audit corrections. |
| `202611200001_database_stabilization.sql` | Added forward-only hardening: active plan/tenant/member checks; active/trialing subscription periods; retired-plan denial; global usage idempotency; concurrency-safe quota accounting; exact retry replay and conflict rejection; one-time invoice lines/totals; explicit subscription transitions and replacement behavior; grant status controls and immutable grant terms; scope and membership-reactivation cleanup; serialized invitation creation/acceptance; and Owner-only Subowner lifecycle enforcement. Existing rows and legacy entitlement records are retained. |

## Confirmed defect and corrections

The exact migration chain previously stopped in `private.can_access_hse()` with SQLSTATE `42601` (`syntax error at end of input`). The original line omitted two closing parentheses for the enclosing membership predicate and SQL expression. The checked-in line adds exactly those two parentheses. No table, policy, object name, or authorization rule in migration 001 was redesigned or removed.

Migration 004 also closes correctness gaps found during the stabilization review: past-due/suspended subscriptions no longer occupy the active/trialing uniqueness slot; retired plans cannot keep access alive; usage retries compare the complete accepted request payload before checking the now-exhausted quota; simultaneous quota requests serialize on a quota key; invoice retries return the original line and increment totals once; and reactivated memberships cannot regain old roles or scopes.

## Files changed in this stabilization

- `.github/workflows/database.yml` — run the independent concurrency harness after the full database test suite; always stop the disposable stack.
- `.gitignore` — exclude Supabase CLI's generated local `.branches/` and `.temp/` state.
- `scripts/check_database_contract.ps1` — check security/migration markers, CI harness presence, and exact pgTAP plan count.
- `scripts/test_database_concurrency.ps1` — use independent local PostgreSQL sessions to test quota, usage idempotency, invoice idempotency, and concurrent invitation acceptance.
- `supabase/migrations/202611190001_sentriq_hse.sql` — the syntax-only correction described above.
- `supabase/migrations/202611200001_database_stabilization.sql` — forward-only database corrections.
- `supabase/tests/database/entitlements_rbac.test.sql` — expanded to 197 synchronized pgTAP assertions.
- `DATABASE_COMPATIBILITY.md` and `supabase/README.md` — updated migration, Supabase dependency, rollout, and integration contracts.
- `IMPLEMENTATION_REPORT.md` — this report.

Migrations 002 and 003 were not modified in this stabilization commit. The `sentriq_ui` repository was not modified.

## Verification performed locally

All commands below targeted the disposable local Supabase stack only:

| Check | Result |
|---|---|
| Static database contract | PASS — 37 contract markers; broad-policy regression guards; service-role-only usage recording; 197 planned and detected assertions. |
| `supabase db reset --local` | PASS — recreated the local database and applied migrations 001, 002, 003, and 004 in order from empty. |
| `supabase test db --local` | PASS — `Files=1, Tests=197, Result: PASS`. |
| Parallel database harness | PASS — 12 simultaneous quota requests produced exactly 3 successes at quota 3; exact retry and payload conflict behavior passed; 8 simultaneous invoice retries produced one line and one total increment; simultaneous invite acceptance produced one winner. |
| `supabase db lint --local --fail-on error` | PASS — no schema errors found. |
| `git diff --check` | PASS — no whitespace errors. |

The first GitHub run [44635637902](https://github.com/elmasry-platform/sentriq/actions/runs/44635637902) passed migration reset and all 197 pgTAP assertions, but exposed a harness bug: it sometimes selected a generated idempotency key whose request had been denied by quota. The worker now returns its key with its result, and retry/conflict checks use a confirmed successful request. The corrected implementation commit `7c7aa00e389a0ea4a981415052e43c8de8b2264a` passed both GitHub jobs in [run 44636378060](https://github.com/elmasry-platform/sentriq/actions/runs/44636378060). Job-level evidence: `static-contract` succeeded; `supabase-database` succeeded with all four migrations applied, `Files=1, Tests=197, Result: PASS`, the concurrency harness passing, and the always-run stop step succeeding. The workflow has separate static and Supabase database jobs; the database job starts an isolated stack and stops it with `if: always()`.

## Remaining limits and security concerns

- The database does not provide a trusted application server. Invitation RPCs and usage/billing RPCs are service-role-only; a future server must validate bearer tokens with Supabase Auth, derive identity server-side, and never expose the service-role key to a browser.
- The UI still uses mock/local data and has no live Supabase adapter. No Laravel/API pages or frontend integration were added.
- Invitation email delivery, Copilot model execution, payment collection, tax handling, and production price configuration are not implemented. No production price or legacy billing value was invented.
- HSE coverage remains forms, published form versions, inspections, reviews, findings, corrective actions, follow-ups, and evidence metadata. Incidents, near misses, permits, compliance audits, and risk assessments remain future scope unless separately implemented.
- Local migration/test success is not a production-readiness claim. Hosted credentials, data migration rehearsal, operational backup/recovery, trusted-server integration, and deployment review remain outside this change.

## Merge readiness

**PASS for review/merge of the database implementation.** Both workflow jobs passed on the corrected implementation commit; no merge, deployment, or hosted database change was performed. Production readiness remains out of scope until the documented trusted-server, UI, operations, and provider integrations are implemented and reviewed.

## Foundation security remediation follow-up

The prior implementation results above describe the earlier changeset and are preserved as historical evidence. On `codex/foundation-security-remediation`, forward migration `202611200002_foundation_security_remediation.sql` closes F-01 and F-02, P-05 defaults/catalog checks are added, and F-03 cleanup is deterministic on success and injected failure. The expanded 242-assertion pgTAP suite passed three times after a fresh reset; the repeat sequence, actual-role security probes, catalog checks, failure cleanup check, and database lint all passed locally. Current SHA, CI run, PR link, and remaining integration gates are in `REMEDIATION_RESULTS.md`.
