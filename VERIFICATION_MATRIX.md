# SENTRIQ Verification Matrix

This matrix records the local evidence from `codex/security-review-adr` at implementation commit `c8019cb2e73b4615ca05f24c91a18e510fe69d72`. Synthetic fixtures are used. No hosted or customer data was accessed.

## Environment and commands

| Check ID | Exact command | Result | Evidence / limitation |
|---|---|---|---|
| ENV-01 | `git fetch origin` then `git rev-parse HEAD`, `git rev-parse origin/codex/platform-entitlements-rbac`, `git rev-parse origin/main` | PASS | HEAD and remote feature branch both `c8019cb2e73b4615ca05f24c91a18e510fe69d72`; main `b5a16e42ecabe1b4d7b1c16c46b2442bb3870efd`; six ahead, zero behind. |
| ENV-02 | `Test-Path supabase/.temp/project-ref`;`npx supabase status --output json` | PASS | No linked `project-ref`; CLI target was `local`. Status output contained disposable local credentials and was not copied into this report. |
| ENV-03 |`npx supabase db reset --local` | PASS | Recreated local database and applied `202611190001_sentriq_hse.sql`, `202611190002_commercial_entitlements_rbac.sql`, `202611190003_security_remediation.sql`, and `202611200001_database_stabilization.sql` from empty. |
| ENV-04 | `docker exec supabase_db_sentriq psql -X -qAt -U postgres -d postgres -c "select current_setting('server_version');"` | PASS | PostgreSQL 15.20. This validates local PostgreSQL major compatibility, not Supabase-hosted managed behavior. |
| ENV-05 |`npx supabase db lint --local --fail-on error` | PASS |`No schema errors found` across `api`, `audit`, `core`, `extensions`, `hse`, `iam`, `private`, and `public`. CLI warned that `--local` is redundant. |
| ENV-06 | Catalog queries against `pg_class`, `pg_policies`, `pg_views`, `pg_proc`, and `pg_roles` | PASS | 39 application tables; zero without both RLS and FORCE RLS; zero final `FOR ALL` policies; zero API views without invoker security; 47 SECURITY DEFINER functions, all owner `postgres`, fixed empty search path, no PUBLIC/anon execution. `authenticated`/service grants are inventoried in `SECURITY_REVIEW.md`. Catalog evidence is not an ordinary-user query test. |
| ENV-07 | `scripts/check_database_contract.ps1` | PASS | 37 static contract markers, dropped broad policies not reintroduced, service-role-only usage recording, concurrency harness present, and 197 synchronized pgTAP assertions. |

The catalog command for ENV-06 was a read-only SQL batch piped to local psql:

```powershell
@'
select 'app_tables='||count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname in ('core','iam','hse','audit') and c.relkind='r';
select 'rls_unforced='||count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname in ('core','iam','hse','audit') and c.relkind='r' and (not c.relrowsecurity or not c.relforcerowsecurity);
select 'policies_for_all='||count(*) from pg_policies where schemaname in ('core','iam','hse','audit') and cmd='ALL';
select 'api_views_not_invoker='||count(*) from pg_views v where v.schemaname='api' and not coalesce((select c.reloptions @> array['security_invoker=true'] from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=v.schemaname and c.relname=v.viewname),false);
select 'app_secdef='||count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('api','private') and p.prosecdef;
select 'secdef_bad_owner='||count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('api','private') and p.prosecdef and pg_get_userbyid(p.proowner)<>'postgres';
select 'secdef_missing_fixed_path='||count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('api','private') and p.prosecdef and coalesce(array_to_string(p.proconfig,','),'') not like '%search_path=%';
select 'secdef_anon_executable='||count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('api','private') and p.prosecdef and has_function_privilege('anon',p.oid,'EXECUTE');
select n.nspname||'.'||p.proname||'|'||has_function_privilege('authenticated',p.oid,'EXECUTE')||'|'||has_function_privilege('service_role',p.oid,'EXECUTE')||'|'||has_function_privilege('public',p.oid,'EXECUTE') from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('api','private') and p.prosecdef order by 1;
'@ | docker exec -i supabase_db_sentriq psql -X -qAt -U postgres -d postgres
```

The command runs as local postgres for catalog visibility; it is inspection evidence only, not proof of ordinary-role RLS behavior.

## Security requirements and scenarios

| Test ID | Requirement / attack scenario | Actor, tenant, target | Expected | Actual | Command / evidence | Result and limitation |
|---|---|---|---|---|---|---|
| RLS-01 | Guess Company B tenant UUID and read its tenant/site through base table and API view | Company A authenticated Superadmin; Company B tenant, site, `api.v_sites` row | No rows | 0 tenant, site, and view rows | `scripts/security_review_probes.ps1`; SQL runs under `SET ROLE authenticated` | PASS. One synthetic tenant pair; does not exercise every table. |
| RLS-02 | Update Company B site by exact UUID | Company A authenticated Superadmin; Company B `core.sites` row | No row changed | 0 updated rows | `scripts/security_review_probes.ps1` | PASS. |
| RLS-03 | Insert/delete Company B site | Company A authenticated Superadmin; Company B `core.sites` | Deny | Both blocked with insufficient privilege | `scripts/security_review_probes.ps1` | PASS. Fixture creator runs as local postgres; attack DML runs as authenticated. |
| RLS-04 | Guess direct UUIDs for HSE children | Company A authenticated Superadmin; Company B inspection, finding, action, action update, follow-up | No rows | 0 rows for every exact UUID | `scripts/security_review_probes.ps1` | PASS. Does not probe every child-table write path. |
| STORAGE-01 | Read Company B evidence metadata by UUID | Company A authenticated Superadmin; Company B `hse.evidence_files` row | No rows | 0 rows | `scripts/security_review_probes.ps1` | PASS. SQL RLS only. |
| STORAGE-02 | Read Company B private object by bucket and exact key | Company A authenticated Superadmin; Company B `storage.objects` row | No rows | 0 rows | `scripts/security_review_probes.ps1` | PASS. Supabase Storage HTTP API, byte upload, signed URL issuance/expiry, and revocation were not exercised. |
| IAM-01 | Insert an active membership directly without invitation | Tenant A authenticated Company Superadmin; existing Auth user UUID; `iam.memberships` | Deny; invitation acceptance required | Row inserted with `status=active` | `scripts/security_review_probes.ps1` | **FAIL — confirmed F-01.** Rollback-only synthetic fixture. |
| IAM-02 | Activate an invited row directly | Tenant A authenticated Company Superadmin; existing invited membership | Deny; token/email acceptance required | Update sets `status=active` | `scripts/security_review_probes.ps1` | **FAIL — confirmed F-01.** The invitation record is not accepted by this path. |
| IAM-03 | Confirm the uninvited identity gains tenant access after direct insert | Newly added Auth identity under authenticated role; Tenant A | No tenant access until verified acceptance | Tenant row becomes visible (count 1) | `scripts/security_review_probes.ps1` | **FAIL — confirms impact of F-01.** The row is rolled back after the probe. |
| IAM-04 | Company Admin tries role/scope/platform/commercial changes | Company Admin in Tenant A; role assignments, site access, Superadmin management, internal billing tables | Deny | pgTAP assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (named assertions at lines 261–274);`npx supabase test db --local` | PASS, 197 total assertions. Test uses authenticated role for these assertions. |
| IAM-05 | Platform Owner/Subowner hierarchy | Owner and Subowner authenticated identities; platform roster and cross-tenant grants | Owner alone creates/reactivates/deactivates Subowners; Subowner cannot manage roster | All named assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 447–490) | PASS. No hosted operator MFA policy was available. |
| IAM-07 | Company Superadmin attempts to create or manage a Subowner | Tenant A authenticated Company Superadmin; `iam.platform_operators` and `api.manage_subowner` | Deny | Both RPC call and direct roster insert are blocked | `scripts/security_review_probes.ps1` | PASS. Executed with actual `authenticated` SQL role. |
| SEC-01 | Anonymous caller reads internal commercial data or invokes billing/invitation RPCs | `anon` role; plans, invoices, usage, `api.record_feature_usage`, `api.accept_invitation` | No table privileges or function EXECUTE | Denied by grants/ACL checks | `supabase/tests/database/entitlements_rbac.test.sql` (lines 441–442) | PASS. Privilege assertions run in the SQL test harness; no hosted anonymous request was made. |
| IAM-06 | Suspended user retains access or gains stale access on reactivation | Suspended/reactivated employee; tenant, HSE roles, sites, org units, task assignments | Suspension denies; reactivation clears previous authorizations | Assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 339–408) | PASS. Tested through SQL helper/role contexts, not hosted token revocation. |
| SCOPE-01 | Tenant/site/org-unit/task permission intersection | Employee with several functional roles; correct and incorrect site, org unit, task IDs | Allow exact intersections only; task assignment must not bypass site/org restriction | Matching access allowed; wrong site/unit, revoked scope, wrong/unassigned task denied | `supabase/tests/database/entitlements_rbac.test.sql` (lines 376–408) | PASS for named vectors. Also validates cross-tenant task references and site rebind constraints. Does not cover all future Operations entities. |
| SCOPE-02 | Multiple roles or a functional role attempts to become a management role | Employee with multiple roles; membership role row | Multiple functional roles may coexist; cannot change Company management level | Assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 196–200) | PASS. |
| ENT-01 | HSE subscription/module automatically enables Copilot | Company Superadmin/employee in Tenant A; module and feature entitlements | HSE alone does not enable Copilot; feature plus permission/scope required | Named assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 96–99, 159–209) | PASS. The untested membership-scoped module grant behavior is F-02. |
| ENT-02 | Membership grant leaks to another member or tenant; expired/revoked/suspended grant remains active | Superadmin and employees across Tenant A/B | Exact recipient only; invalid grant immediately denied | Named assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 165–194) | PASS for feature grants. Module membership grants were not included in this suite. |
| ENT-05 | Issue a member-scoped HSE module grant and query its effective state | Authenticated platform Owner issues grant for Tenant A Superadmin; target is the same membership | If membership-scoped module grants are supported by the RPC contract, target module entitlement should be true and other members remain false | Grant RPC accepts it; target effective HSE module entitlement is false | `scripts/security_review_probes.ps1` | **FAIL — confirmed F-02 behavior mismatch.** Product intent for module-level member scoping needs owner confirmation; the isolated transaction rolls back. |
| ENT-03 | Canceled/suspended/past-due/expired/future subscription or retired plan still authorizes | Platform operator; synthetic tenants/plans/subscription periods | Only effective current active/trialing rows authorize | Named assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 126–157) | PASS. Future active subscription reservation of unique slot remains P-04. |
| ENT-04 | Tenant user reads internal price/quota/invoice/payment details | Company Superadmin, Admin, Employee; plans, rates, usage, invoice, payment tables | No rows | pgTAP assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 261–276, 435–445) | PASS. Table grants alone are still constrained by RLS. |
| INV-01 | Raw token storage, unverified/wrong email, replay, revocation, level escalation, cross-tenant revoke | Company Superadmin/service RPC; synthetic invite and Auth identities | Hash only; verified matching email; one-use; intended level only; cross-tenant denied | Named assertions pass | `supabase/tests/database/entitlements_rbac.test.sql` (lines 226–250) | PASS. Service RPC body tests use a postgres connection with service-role claim; the claim does not test service_role SQL ACL by itself. |
| INV-02 | Two concurrent invitation acceptances | Trusted service invocation; same invitation token/user | Exactly one acceptance | One success, one invalid/expired; one membership and one accepted invite | `scripts/test_database_concurrency.ps1` | PASS. Harness connects as postgres and sets the service-role JWT claim; it is not an actual service_role SQL session. |
| AUD-01 | Mutate/delete audit or immutable business records; expose arbitrary sensitive values in diffs | Authenticated user; audit, usage, invoice, review history | Mutation/delete denied; allowlisted diff only | pgTAP verifies immutable ledgers and safe changed-field object | `supabase/tests/database/entitlements_rbac.test.sql` (lines 200, 433–446) | PASS for covered records. Hosted actor attribution/retention remain unverified. |
| USE-01 | Duplicate usage, exact retry after quota exhaustion, conflicting payload | Trusted metering RPC; tenant/member/feature/idempotency key | Exact retry returns original event; conflict denied; quota never exceeded | One row per key; exact retry same event; conflicts rejected | pgTAP lines 215–221 and `scripts/test_database_concurrency.ps1` | PASS. Concurrency uses service-role claim through a postgres SQL connection. |
| USE-02 | Concurrent quota overrun and invoice duplicate/total overcount | Trusted metering/invoice RPCs; 12 concurrent requests, quota 3; 8 invoice retries | Exactly 3 usage successes; one invoice item and one amount increment | 3 successes, 9 quota denials; invoice totals 7 once | `scripts/test_database_concurrency.ps1` | PASS. Synthetic fixture rows persist, causing F-03. |
| HSE-01 | Illegal review stage, stale reviewer revision, unauthorized reviewer, status bypass | Employee/reviewer; synthetic inspection in Tenant A | Reject wrong stage/stale revision/unauthorized transition; legal stage chain advances | Named pgTAP assertions pass through reviewer 1, reviewer 2, final reviewer, and return | `supabase/tests/database/entitlements_rbac.test.sql` (lines 409–432) | PASS for tested states. Direct arbitrary status writes and every state/role combination are not exhaustively enumerated. |

## Test harness notes

| Run | Command | Result |
|---|---|---|
| Clean baseline pgTAP |`npx supabase db reset --local` then`npx supabase test db --local` | PASS: 197/197. |
| Concurrency | `scripts/test_database_concurrency.ps1` | PASS: 12 usage requests with quota 3; exact retry; conflicting payload; 8 invoice retries produce one line; concurrent invite acceptance has one winner. |
| Negative scope, authority, membership, and entitlement probe | `scripts/security_review_probes.ps1` | Cross-tenant reads/writes blocked; Company Superadmin platform operations denied; F-01 insertion/activation succeeds and target sees tenant; membership-scoped module grant accepted but ineffective. Probe transaction rolls back. |
| Repeat pgTAP without reset after concurrency |`npx supabase test db --local` | FAIL: 4 exact-count assertions; 193/197 pass because the concurrency fixture tenant and invoice item persisted.`npx supabase db reset --local` then restored 197/197. This is F-03, not a migration failure. |
| Formatting check | `git diff --check` | PASS. |

## Not verified

- Hosted Supabase PostgreSQL/Auth/Storage or any production project.
- Laravel middleware, AccessResolver, direct-DB connection role, connection pool state, or service-key custody; backend is not present.
- Actual Supabase Auth JWT signature/issuer/audience validation, refresh/logout revocation, MFA/AAL enforcement, SSO, recovery, or account lifecycle configuration.
- Storage HTTP upload/download and signed-URL lifetime/revocation.
- Every possible HSE table write and invalid composite-key tuple; the exact cross-tenant reads probe covers representative child records, not every statement.
- Future Operations module policy parity.

## Foundation remediation follow-up

The matrix above preserves the historical security-review baseline. The following evidence is from `codex/foundation-security-remediation`, based on the audit commit `31368375fa4c4fcafd9f5a6d2078b2dc79ced854`; see `REMEDIATION_RESULTS.md` for the complete record and current CI link.

| Check | Actual role / command | Result |
|---|---|---|
| F-01 direct membership insert, invited/suspended activation, identity/role/email/profile changes, and cross-tenant update | `SET ROLE authenticated`; Company Superadmin context | PASS — table privileges and policies deny the writes. Company Admin and Employee management attempts also fail. `anon` direct insert/update attempts fail under actual `SET ROLE anon`. |
| F-01 service lifecycle RPC | `SET ROLE service_role` with service-role JWT claim | PASS — Company Superadmin can suspend/end an eligible lower-level member; Company Admin/Employee actors, cross-tenant targets, self-suspension, Company Superadmin targets, and activation requests are denied. Valid verified invitation acceptance still succeeds; wrong/unverified/expired/reused cases fail. |
| F-02 module and feature grant contract | `SET ROLE authenticated` for platform grant RPC; `postgres` for direct constraint assertion | PASS — company module grant accepted; membership-scoped module grant denied by RPC and table constraint; member feature grant accepted but parent module is required and the grant does not leak to another membership. |
| P-05 SECURITY DEFINER catalog/defaults | `postgres` catalog verification and temporary function creation; ACL checks for `anon`, `authenticated`, and `service_role` | PASS — exact authenticated and six-function service allowlists; owner=`postgres`; empty fixed `search_path`; explicit ACLs; no PUBLIC/anon execution; temporary api/private functions not executable by Supabase roles. |
| pgTAP suite | Actual SQL roles `anon`, `authenticated`, and `service_role`; `postgres` only for fixtures | PASS — 242/242 on all three runs after the fresh reset. A test-only transaction grants service-role SELECT for result inspection and rolls it back. |
| Security probes | `scripts/security_review_probes.ps1`; attacks run under actual `SET ROLE authenticated` | PASS — direct membership activation blocked, uninvited user sees zero tenant rows, cross-tenant reads/writes remain denied, membership-scoped module grant rejected. |
| Concurrency run 1 | `scripts/test_database_concurrency.ps1`; worker SQL sessions use actual `SET ROLE service_role` | PASS — quota/idempotency, eight invoice retries, and one-winner invitation acceptance; exact fixture and associated audit cleanup found zero rows. |
| Failure cleanup | `scripts/verify_database_concurrency_failure_cleanup.ps1` | PASS — injected failure after fixture setup exited nonzero; `finally` cleanup verification found zero fixture and audit rows. |
| Concurrency run 2 and repeat pgTAP | Same harness followed by `npx supabase test db --local` without reset | PASS — cleanup found zero rows; pgTAP 242/242. |
| Static contract and database lint | `scripts/check_database_contract.ps1`; `npx supabase db lint --local --fail-on error` | PASS — migration/test/workflow contract and assertion count synchronized; no schema errors. |

Local validation used only the disposable local Supabase stack. Hosted JWT validation, Laravel actor provenance, MFA/AAL policy, hosted PostgREST/Storage behavior, hosted migration-owner confirmation, and production data preflight remain unverified integration gates.
