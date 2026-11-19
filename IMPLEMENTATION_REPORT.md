# SENTRIQ Phase 2 implementation report

## A. Executive disposition

**FAIL — REMEDIATION REQUIRED.** The Phase 2 security changes are implemented and all 119 pgTAP assertions passed against a disposable diagnostic copy. The exact checked-in chain still cannot apply from empty because immutable migration `202611190001_sentriq_hse.sql` has a PostgreSQL syntax error in `private.can_access_hse()` (SQLSTATE 42601). The Phase 2 instruction expressly prohibits changing that migration. Therefore the repository migration chain and its database CI job cannot meet the acceptance criteria under the current constraint. Migration 001 remains byte-for-byte unchanged.

## B. Change summary

| Finding | Root cause | Correction | Compatibility impact |
|---|---|---|---|
| Suspended module grant could remain effective | The earlier grant branch did not consistently require active status. | `202611190003_security_remediation.sql:4–20` requires an active tenant and globally enabled module; grants must be active, unrevoked, started, and unexpired. Subscription access checks active/trialing status and current subscription/item periods. | Suspended, revoked, expired, future, or globally disabled access now denies synchronously. Legacy entitlement rows and their traceable backfill remain intact. |
| Role Site/Organization Unit scope did not resolve | Role permission rows contain reusable permission definitions, not per-assignment site/unit IDs; the old evaluator compared NULL placeholders to requested scopes. | `202611190003_security_remediation.sql:23–124` adds tenant-safe role-site and role-unit binding tables and evaluates those bindings for each role assignment. Independent member site/unit grants remain required. | Existing role permissions scoped to a site or unit need explicit assignment bindings. No permission rows are cloned; no scope is inferred for existing data. |
| Tenant and task scopes could be mixed incorrectly | Access must intersect a valid role/direct permission, tenant, site access, org-unit access where applicable, and a validated assigned task. | `202611190003_security_remediation.sql:82–124` evaluates reusable role permissions separately from exact assignment bindings. Task assignment still requires matching task kind/ID/site and applicable org-unit access. | Role union stays separate from management level. Expired/revoked role assignments and scope bindings cease authorizing access. |
| Commercial prices and financial rows were visible to company principals | Active plan/catalog policies were broader than the documented Owner/Subowner boundary. | `202611190003_security_remediation.sql:126–144,191–217` restricts catalog and financial RLS to platform operators. The Company Superadmin RPC returns only effective module/feature booleans for that caller's tenant. Internal entitlement helper functions are not directly executable by authenticated users. | Company members retain only the information needed to administer their own effective access; platform price and billing detail is hidden. |
| Expired invitation blocked reinviting the same address | Pending-invitation uniqueness did not safely handle time-dependent expiry. | `202611190003_security_remediation.sql:146–164` closes expired pending invitations transactionally before inserting a reinvitation; no volatile `now()` partial-index predicate is used. Raw tokens remain service-role-only and stored tokens remain hashes. | The trusted Edge Function/Laravel/API server must validate the caller JWT, derive actor identity, and keep service-role credentials server-side. Email delivery remains unimplemented. |
| Invoice RPC ACL was ordered before the function existed | Migration 002 revoked/granted `api.invoice_usage_event` before defining it, aborting migration execution. | `202611190002_commercial_entitlements_rbac.sql:742–810` places invoice RPC ACL statements after the function definition. | No API behavior changes; this is required for the migration to proceed. |
| Commercial feature access must be membership-specific | A functional Copilot role alone is not a commercial grant. | `supabase/tests/database/entitlements_rbac.test.sql:133–161` covers a Copilot grant to one Company Superadmin, an employee with the functional permission but no feature grant, expiration, tenant isolation, and usage-rate snapshots. | No Copilot grant is inferred from HSE or from a functional role. |

Changed implementation files: `supabase/migrations/202611190002_commercial_entitlements_rbac.sql`, new `supabase/migrations/202611190003_security_remediation.sql`, `supabase/tests/database/entitlements_rbac.test.sql`, `scripts/check_database_contract.ps1`, `supabase/README.md`, and `DATABASE_COMPATIBILITY.md`. The UI repository was not modified.

## C. Test evidence

The 119 assertions below all passed in a **disposable diagnostic copy** where the missing parentheses were added only to a temporary copy of migration 001. They do not establish that the checked-in migration chain applies. Exact-chain evidence is listed after the table.

| Test | Expected | Actual | Result | Evidence |
|---|---|---|---|---|
| Suspended module grant | Deny | Denied | PASS† | pgTAP 119/119 |
| Expired Copilot grant | Deny | Denied | PASS† | pgTAP 119/119 |
| Membership-specific Copilot grant | Exact member only | Superadmin entitled; employee and other tenant denied | PASS† | pgTAP 119/119 |
| Role multi-assignment | Allow permission union without management escalation | Multiple roles work; membership remains Employee | PASS† | pgTAP 119/119 |
| Site scope | Exact assigned sites only | Authorized site allowed; other site denied | PASS† | pgTAP 119/119 |
| Organization Unit scope | Exact unit only | Bound unit allowed; different unit denied | PASS† | pgTAP 119/119 |
| Task + Site intersection | Both required; only assigned task | Missing site denied; assigned task allowed; other task/site denied | PASS† | pgTAP 119/119 |
| Commercial confidentiality | Company members denied internal catalog/financial data | Company Admin, Employee, and Superadmin queries return no protected rows; catalog RLS and RPC paths checked | PASS† | pgTAP 119/119 |
| Invitation expiry/replay | Deny stale/replayed tokens; allow eligible reinvite | Expired/revoked/replayed, wrong-email, unverified-email, forbidden-level, and cross-tenant cases denied; expired-address reinvite allowed | PASS† | pgTAP 119/119 |
| Reviewer 1 approval/return | Correct stage transitions | Approval advances; return is retained; Reviewer 2 and Final Reviewer transitions pass | PASS† | pgTAP 119/119 |
| Cross-tenant access | Deny | Role/tenant/invitation access denied across tenant IDs | PASS† | pgTAP 119/119 |
| Hard delete | Deny and audit | Authenticated DELETE is unavailable; audit ledger rejects deletion; safe audit diffs are present | PASS† | pgTAP 119/119 |
| Owner/Subowner lifecycle | Owner only | Owner creates/deactivates Subowner; Subowner cannot manage operator roster | PASS† | pgTAP 119/119 |
| Usage idempotency | One event for a repeated request | One event for repeated key; changed payload and prompt content denied | PASS† | pgTAP 119/119 |
| Invoice idempotency | One line item | Repeated invoice call leaves one line item at exact rate snapshot | PASS† | pgTAP 119/119 |
| Checked-in migration chain | Apply from empty database | Fails in migration 001 before 002/003 | FAIL | Local `supabase start`; SQLSTATE 42601 in `private.can_access_hse()` |
| Exact-chain GitHub Actions | Static and database jobs green | Baseline database job fails at the same migration 001 parse error | FAIL | [Actions run 44563250811](https://github.com/elmasry-platform/sentriq/actions/runs/44563250811) |

† Diagnostic copy only. Local evidence: Supabase CLI 3.2.0 and Docker 29.4.0; disposable `db reset` applied migrations 001–003 in the copied project and `supabase test db --local` reported `All tests successful`, `Files=1, Tests=119`, `Result: PASS`. The exact checked-in project was also attempted locally; its `supabase start` stopped at migration 001 with `syntax error at end of input` before pgTAP could start. The diagnostic copy and local stack were stopped afterward. No hosted Supabase project was linked.

The static contract check passed with 31 markers, guarded policy checks, service-role-only usage recording, and a synchronized 119 assertion plan. `git diff --check` passed; Git emitted only line-ending normalization notices.

## D. Remaining blockers and unverified work

- The original migration 001 must receive an authorized syntax correction before the exact branch can apply or the database CI job can pass. It was not modified in this phase because the supplied execution order forbids it.
- The diagnostic pgTAP pass is not a substitute for a green empty-database run against the exact checked-in chain.
- Concurrency races for simultaneous invitation acceptance, subscription creation/renewal, quota exhaustion, and invoice calls were not exercised; current idempotency assertions are sequential.
- Subscription replacement/renewal, duplicate live subscriptions, complete Owner/Subowner access across every tenant table, and full Company Admin/Superadmin capability matrices need further acceptance testing.
- No live UI/Supabase adapter, trusted Copilot server, invitation email delivery, payment gateway/collection, production pricing, or tax rules are implemented.
- Current HSE database/UI scope covers forms, versions, inspections, reviews, findings, corrective actions, follow-ups, and evidence metadata. Other HSE areas and future Operations/ERP modules remain outside this implementation.

## E. Deployment status

**NOT DEPLOYED — NO HOSTED OR PRODUCTION DATABASE WAS MODIFIED.** No merge or deployment was performed.
