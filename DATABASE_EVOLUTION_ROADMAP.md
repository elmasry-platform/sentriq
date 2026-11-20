# SENTRIQ Database Evolution Roadmap

## Roadmap principles

- Sequence by prerequisites and verified customer workflows; no dates or budgets are implied.
- Preserve the current migration chain and customer rows. Use forward-only, additive migration plans with explicit backfill, validation, rollback/forward-recovery and eventual contract steps.
- Every new tenant-owned table requires tenant RLS enabled and forced, least-privilege grants, same-tenant FK design, positive/negative policy tests and API-path review.
- Keep module authorization as company-level and feature exceptions membership-specific only. A feature cannot bypass its parent module.
- Keep business entities typed and normalized. Use JSONB for truly variable/versioned structures with schema validation, not as an unbounded substitute for domain entities.
- Laravel/API action checks and PostgreSQL RLS/invariants are complementary. Never use UI visibility as authorization.
- Do not implement future ERP modules merely because they appear in this roadmap.

## Phase 0 — Close existing security and verification findings

**Entry evidence:** The latest recorded independent review flags F-01 as a Medium blocker and records F-02/F-03 and P-01 through P-05. No remediation is performed by this documentation branch.

1. **Close F-01 membership activation bypass.**
   - Revoke authenticated direct membership INSERT and constrain management updates to safe fields.
   - Route provisioning/status transitions through narrowly granted server operations.
   - Keep invitation acceptance as the path that activates an invited member after one-time token, expiry, and verified matching Auth email.
   - Bind actor/user IDs to a validated token/session, not request JSON.
   - Add negative/positive database tests for direct insert, invited-to-active, suspended-to-active, email/role changes and invitation acceptance.
2. **Close F-02 commercial contract mismatch.**
   - Reject membership-scoped module grants at grant command validation.
   - Retain tenant and membership feature grants.
   - Test parent module requirement, member exception allow, and module/member scope denial.
3. **Resolve platform session assurance (P-03).**
   - Require MFA/step-up for Owner/Subowner sessions and high-impact grants/lifecycle actions.
   - Verify the application and privileged DB RPC use the approved AAL/session assurance.
4. **Define the service actor boundary (P-01).**
   - Laravel validates Auth tokens and derives actor identity.
   - Do not expose service_role; use it only for narrow trusted server operations.
   - Record the initiating human separately from service/job identity for jobs and external callbacks.
5. **Harden future SECURITY DEFINER ACLs (P-05).**
   - Set default function privileges for migration owner in api/private to revoke unintended execute grants.
   - Continue granting each RPC to explicit roles and assert exact ACLs in CI.
6. **Clarify bootstrap privilege (P-02).**
   - Keep bootstrap as an explicit installation operation with strict execute ACL. Do not rely on current_user inside SECURITY DEFINER as caller identity.
7. **Fix test repeatability (F-03).**
   - Isolate or clean concurrency fixtures so local database tests can be repeated in documented order.
8. **Resolve scheduled subscription lifecycle (P-04).**
   - Decide whether future starts are supported; ensure not-yet-started subscriptions do not block the live slot unless intended.

**Exit gate:** Security review confirms F-01 is no longer reachable through table/API paths; entitlement scope behavior is explicit; operator MFA and actor provenance are verified; local tests are repeatable; CI protects policies, ACLs and RLS. This is a gate before onboarding real company users, not a claim that it has been met.

## Phase 1 — Stabilize the shared platform foundation

1. Approve ADR 0001, 0002 and 0003, and record chosen provider, backend trust model, RLS context, storage and scope rules.
2. Implement the trusted Laravel/API adapter:
   - Validate issuer, signature, audience, expiry and required Supabase Auth claims.
   - Use a non-BYPASSRLS user path for ordinary data requests.
   - Do not forward browser-supplied actor IDs or identity GUC values.
   - Ensure transaction-local context is cleared under connection pooling.
3. Build a canonical authorization vocabulary and PHP AccessResolver matching SQL permissions, module/feature keys and scope rules.
   - Compare PHP and PostgreSQL allow/deny vectors.
   - Include cross-tenant, wrong site, wrong org, wrong task, revoked grant, suspended member and feature-without-module cases.
4. Verify every table/view/RPC/API route by action, tenant and scope.
   - Test actual PostgREST list/detail/write paths, not only helper booleans.
   - Retain composites and add only missing composite tenant constraints.
5. Define typed tenant settings and domain ownership verification only after listing actual settings and routing needs.
   - Require DNS or controlled manual proof; do not derive tenant access from email domain.
6. Define tenant closure, retention, export, anonymization and archive policy before data volume grows.
7. Establish audit actor, data-minimization and retention rules. Audit table changes and business workflow histories as separate concerns.
8. Profile supported HSE/core query paths before adding indexes. Decide usage/audit retention and partitioning from volume requirements.

**Migration ordering:** finalize policy/authorization contract -> introduce/validate trusted request adapter -> close F-01/F-02 -> add only approved typed configuration/verification lifecycle -> run policy parity and API tests. Do not move live identities or change Auth provider as a side effect of these changes.

## Phase 2 — Complete the first HSE product slice

HSE scope should be selected from launch-customer workflows; not every capability below must ship together.

1. **Make the current forms usable and reliable.**
   - Version the form-definition schema and publish only validated snapshots.
   - Validate submitted answer shape, required fields, types, conditions and question IDs against the pinned form version.
   - Preserve immutable published snapshots and answer version linkage.
   - Define localization, scoring, conditional fields and repeated groups.
2. **Close inspection lifecycle gaps.**
   - Decide scheduled/recurrent inspections; if needed, separate schedule, generated occurrence and completed inspection.
   - Define timezone, overdue/cancelled behavior, owner/assignee history and reminder triggers.
   - Verify review transition authorization, stage reassignment, return and reopen behavior.
3. **Choose the HSE safety case taxonomy before new tables.**
   - Distinguish inspection finding, standalone observation, incident/near miss and hazard.
   - Specify injury/health privacy, occurrence facts, severity, investigation and regulator reporting.
   - Define risk matrix versioning, inherent/residual risk and control effectiveness.
   - Keep new incident/hazard/risk/control records typed and same-tenant; link corrective action to typed sources or a constrained association model.
4. **Complete corrective action closure if required by launch workflows.**
   - Define cause/preventive action, response/plan/closure due dates, assignee, evidence, verifier, effectiveness check and closure approval.
   - Keep action update and verification history append-only.
5. **Secure and operate evidence.**
   - Exercise actual private Storage upload/download and signed URL paths.
   - Confirm object/metadata consistency, cleanup, file validation, malware scanning, expiry and access revocation behavior.
   - Add version/hash/retention fields only after an approved file lifecycle.
6. **Add other HSE domains in business priority order.**
   - Permit to Work requires authorization, isolation/control checklist, participants, validity and handback.
   - Toolbox Talks require session content/version, attendance acknowledgement and facilitator.
   - Training/competency requires worker identity, evidence and expiry.
   - Compliance audits require obligations, audit program, findings and action linkage.
   - Emergency preparedness requires plan version, drill, participants and after-action workflow.
   - Contractor safety depends on contractor organization/person, qualification and site induction.
7. **Add HSE reporting only against defined decisions and metrics.**
   - Define denominator, scope, status timing and historical snapshot semantics before implementing KPIs.
   - Keep operational queries in OLTP; use an export/reporting pipeline for heavier analytics.

**Migration ordering:** approve lifecycle/domain vocabulary -> add parent typed entity and tenant/site constraints -> add HSE permission keys/RLS -> add workflow/history and evidence links -> add API contract -> test same-tenant and cross-tenant behavior -> backfill legacy records without rewriting their meaning.

## Phase 3 — Add shared enterprise services only after repeat demand

A shared service should be introduced when at least two modules need the same stable concept and security/lifecycle semantics.

- **Task/work queue:** distinct from iam.task_assignments. Define work item, source entity, assignee history, due date, priority, completion, cancellation and tenant access through parent record.
- **Workflow/approvals:** separate versioned workflow definition from workflow instance, step assignment and decision. Module permission and scope still authorize each transition. Do not build a rule language without rule authoring, simulation and test requirements.
- **Notifications:** create event/outbox only when HSE/API operations require reliable asynchronous delivery. Record recipient/channel/delivery attempts, idempotency, retry and dead-letter state. Avoid sensitive payload leakage.
- **Comments/activity:** create only after deciding whether comments need edit/redaction, attachments, mentions, audit and retention. Parent-record permissions remain authoritative.
- **Documents:** generalize only if HSE and another module need the same metadata/version/access lifecycle. Keep file bytes external/private; do not expose by tenant path alone.
- **Integrations/webhooks:** require connector identity, external ID, sync cursor, signing secret in secret manager, verified event delivery, replay protection and retries.
- **Background jobs:** implement job execution records if asynchronous work needs durable lease, attempts, status, cancellation, actor and idempotency.
- **Reporting/exports:** require query authorization, snapshot time, export owner, expiry, download audit and retention. Avoid cross-tenant aggregate leakage.

**Migration ordering:** agree service contract -> identify tenant and parent authorization -> design idempotency/audit -> add table and RLS -> add publisher/consumer code -> retry/replay and access tests -> only then migrate module-specific rows if required.

## Phase 4 — Expand ERP modules in dependency order

### People and HR

Start by specifying employee vs contractor vs non-login worker, employee lifecycle, rehire, organizational hierarchy and privacy. Add tenant-owned person/worker separately from Auth membership. Then add employment episodes, positions, contracts, qualifications, attendance and leave as individually justified workflows. Training/competency may serve HSE after this identity foundation.

### Operations

Define the first customer operation (work order, service job or production activity) before choosing tables. Reuse tenant, site, worker, asset, permissions and audit; do not reuse HSE task assignment as work-order storage. Add operational status/history and link to HSE permit/hazard where the workflow requires it.

### Assets

Establish asset identity, category, lifecycle, location/custody history and maintenance responsibility. Link inspections and work orders through explicit same-tenant asset references. Decide whether asset financial depreciation is an ERP Finance concern or an external system.

### Procurement

Define supplier, sourcing, requisition, purchase order, contract, approval and receipt lifecycle. Requires item/catalog and financial responsibility decisions. Ensure each receipt creates a durable link to the purchase-order line.

### Inventory

Define item/SKU, units/conversions, warehouse/bin, reservation, receipt, issue, transfer, count and adjustment semantics. Keep stock movement as auditable facts; any balance table should be a rebuildable projection with transaction/concurrency controls.

### Finance

Treat this as a separate customer accounting domain, not a continuation of core platform invoices. Before schema work decide legal entities, chart of accounts, journals, fiscal calendars, tax, base/transaction currency, AP/AR, close controls, reversal rules, bank reconciliation, audit and local jurisdiction. If those needs exceed product scope, integrate with an accounting provider through durable external identifiers and reconciliation.

**Dependency sketch:** People/worker -> Operations assignment and HSE training; Assets -> Operations maintenance and HSE asset risk; Procurement -> supplier/item/receipt; Inventory -> item/warehouse/movement; Finance depends on legal entity, fiscal calendar and posting rules across commercial operations.

## Release and migration guardrails

- Preserve the four existing migration files and add changes as reviewed forward-only migrations.
- Prefer expand/backfill/validate/contract over destructive rename/drop, with a compatibility window for UI/API consumers.
- Never use CREATE TABLE IF NOT EXISTS to hide incompatible schema drift in a forward migration.
- Use tenant-qualified foreign keys for same-tenant relationships and targeted constraints for invariant fields.
- For each tenant table, explicitly grant only required operations, enable and FORCE RLS, define policy per operation, and test a direct-ID access attempt.
- For SECURITY DEFINER functions, pin an empty or otherwise explicit search_path, revoke defaults, grant execution narrowly and validate actor/tenant/target relationships inside the function.
- Protect append-only history with database ACL and trigger controls; record business state transitions in domain-owned history.
- Keep customer tests on isolated local/CI databases. No hosted or production migration should be run as part of this audit or roadmap.
