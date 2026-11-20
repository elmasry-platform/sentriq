# SENTRIQ — Enterprise Database Architecture & Domain Coverage Audit

## Executive assessment

SENTRIQ has a meaningful shared-platform and HSE database foundation, but it is not yet a working ERP product or a production-integrated application. The repository contains a Supabase/PostgreSQL migration chain with 39 application-owned tables, normalized tenant commercial entitlements and functional RBAC, tenant-aware relationships, HSE inspection/action workflows, and append-only audit history. It does not contain the Laravel/API service or a live UI adapter, and the UI compatibility document states that the current UI reads mock JSON and browser localStorage.

The current HSE model is a credible first vertical slice for configurable inspection forms, inspections, fixed-stage review, findings, corrective actions, follow-ups, and evidence metadata. It is not a complete HSE management suite: incidents, hazard/risk registers, control measures, permits, HSE training, compliance obligations, emergency drills, contractor safety, and schedules are not represented as complete operational domains.

The strongest architecture direction is already present: platform operators are separate from tenant memberships; functional roles do not represent management authority; module and feature access are separate; membership/site/org/task scopes intersect; and composite tenant foreign keys protect many important relationships. At the audit baseline, blockers included the membership-activation bypass (F-01). The follow-up branch now addresses F-01, F-02, F-03, and P-05 locally. Trusted-server actor provenance, MFA/AAL enforcement, and end-to-end UI/API integration remain open. No claim of full ERP readiness is supported by this repository.

## Audit baseline and method

- Verified source branch: codex/security-review-adr.
- Verified source HEAD and audit base: 6bca0e1dd5e245a278b81fb96d11b23497ec8123.
- The existing SECURITY_REVIEW.md records that its security probes were run against implementation commit c8019cb2e73b4615ca05f24c91a18e510fe69d72. That is distinct from the current source HEAD which includes the committed review record.
- Audit branch: codex/schema-coverage-audit, created from the verified source HEAD.
- Migration source inspected: all four ordered files under supabase/migrations, plus Supabase configuration, API/database compatibility contract, implementation report, existing security review, verification matrix, roadmap, and all three ADRs.
- The current table count was recalculated by counting unique application CREATE TABLE declarations across the migration chain. It is not copied from the older review's table-count statement.
- Prior local catalog evidence is attributed to SECURITY_REVIEW.md and IMPLEMENTATION_REPORT.md. This documentation task did not rerun migrations, connect to a hosted database, or execute tests.
- Constraints, policies, function bodies, triggers, indexes, views, grants, JSONB usage, and storage policies were inspected in migration source. The existing review documents local PostgreSQL catalog counts and prior negative probes. Those prior results are evidence about that recorded run; they are not represented as tests performed during this audit.

### Follow-up security remediation status

The architecture findings below describe the verified audit baseline at `31368375fa4c4fcafd9f5a6d2078b2dc79ced854`; their evidence is retained as history. The follow-up branch `codex/foundation-security-remediation` adds forward migration `202611200002_foundation_security_remediation.sql`. F-01 direct membership writes and activation are closed locally; F-02 module grants are tenant-scoped and member-specific feature grants remain behind their parent module; F-03 exact fixture cleanup works on success and injected failure; P-05 default function ACLs and catalog allowlists are enforced. See `REMEDIATION_RESULTS.md` and `SECURITY_REVIEW.md` for test evidence and remaining hosted/backend gates.

### Migration chain

| Migration | Tables created | Scope |
|---|---:|---|
| 202611190001_sentriq_hse.sql | 22 | Shared core and IAM baseline, nine HSE tables, audit ledger, RLS, HSE authorization helpers/workflows, private evidence bucket, and 12 compatibility views. |
| 202611190002_commercial_entitlements_rbac.sql | 15 | Plans/features/subscriptions/grants/usage/invoices/payments, normalized roles and assignments, invitations, commercial RPCs, and expanded audit fields. |
| 202611190003_security_remediation.sql | 2 | Role-assignment site and organizational-unit scope bindings, entitlement/RLS corrections, and audit coverage. |
| 202611200001_database_stabilization.sql | 0 | Forward-only lifecycle, entitlement, invitation, idempotency, and concurrency corrections. |

### Exact application-owned table inventory

This count excludes Supabase-managed auth and storage tables, views, functions, sequences, and extension objects.

| Schema | Count | Tables and key data represented |
|---|---:|---|
| core | 16 | tenants (name, industry_label, status, creator); org_units (parent, name); sites (org unit, name, code, city, status); tenant_domains (normalized domain, verification status/time); modules (key, label, enabled); tenant_entitlements (legacy tenant/module switch); features (module, key, enabled, usage unit); plans (version, status, price); plan_entitlements (module or feature, quota, usage rate); subscriptions (tenant, plan, status, period); subscription_items (tenant, entitlement, quantity, frozen price and period); entitlement_grants (module or feature, optional membership, period, grantor, reason, billing treatment, payer, status/revocation); usage_events (tenant, beneficiary, feature, grant, payer, idempotency key, quantity, rate, metadata); invoices (tenant, number, status, currency, totals, period); invoice_items (invoice, source, service period, quantity, price); payments (invoice, provider reference, status, amount, metadata). |
| iam | 13 | platform_operators (Auth user, owner/subowner, active lifecycle); memberships (tenant/Auth user, management level, status, display name/email); invitations (tenant, email, hashed token, intended level, acceptance/revocation); site_access; org_unit_access; permission_catalog; member_permissions (direct grants and scope); roles; role_permissions; membership_roles (time-bounded/revocable assignment); membership_role_sites; membership_role_org_units; task_assignments (HSE task kind/id, tenant, member, site/org context). |
| hse | 9 | form_templates (localized title, definition, status/revision/owner); form_versions (versioned immutable snapshot); inspections (tenant/site/template/version/inspector/status/stage/answers/revision); inspection_reviews (stage, decision, actor, reason, revision); findings (inspection/question/site, priority, status); corrective_actions (finding/inspection/site, owner, priority/status/due dates/revision); action_updates (actor, status/comment history); follow_ups (action, owner, due date, status/outcome); evidence_files (tenant/site, linked target, private object key, file metadata/status/uploader). |
| audit | 1 | events (tenant or platform scope, actor user/membership, request id, action, record type/id, JSONB summary, created time). |

The application table distribution is core 16 + iam 13 + hse 9 + audit 1 = **39**. The external identity principal is Supabase Auth’s auth.users; Storage bucket/object rows are Supabase-managed and are not included in the 39. No application enum type or materialized view is created in the migrations. Lifecycle values are primarily text columns constrained by CHECK conditions.

### Constraint, index, security and API inventory

The prior security review records 39 primary-key constraints, 39 unique constraints, 115 foreign-key constraints, and 103 CHECK constraints from the local PostgreSQL catalog after applying the reviewed migration chain. The migration source declares these explicit named indexes (unique constraints and primary keys create their own backing indexes):

- Authority/lifecycle: platform_single_active_owner, one_active_company_superadmin, one_live_subscription_per_tenant.
- IAM: member_permission_unique, roles_global_key, roles_tenant_key, membership_role_active_unique, invitation_one_pending.
- Commercial correctness: entitlement_grants_active_idx, invoice_usage_once, usage_events_idempotency_key_global.
- HSE access/reporting: inspections_site_created_idx, inspections_status_idx, findings_status_idx, actions_status_idx, actions_owner_idx, follow_ups_due_idx, evidence_link_idx, audit_tenant_created_idx.
- The member_permission_unique index is replaced with a wider expression index when org-unit/task dimensions are added. Role-scope uniqueness is represented by table UNIQUE constraints. Most other uniqueness is expressed by primary/unique constraints, including tenant-qualified codes and identifiers.

All 39 application tables were recorded as both RLS-enabled and FORCE RLS in the prior local catalog review. The stabilized policy set removes broad FOR ALL paths for the specific hardened tables identified by the review, revokes authenticated/anon DELETE on core/iam/hse/audit, and limits writes to explicit policies or narrow RPCs. RLS does not constrain postgres, supabase_admin, service_role, or another BYPASSRLS connection; trusted service operations remain a separate boundary.

The migration creates 12 API compatibility views in schema api: v_workspaces, v_sites, v_memberships, v_forms, v_inspections, v_inspection_reviews, v_findings, v_actions, v_follow_ups, v_action_updates, v_evidence, and v_audit_events. They are declared security_invoker=true and granted to authenticated. No materialized view is created. The configured PostgREST exposure includes api/core/iam/hse/audit and excludes private. The database remains Supabase-dependent through auth.users/auth.uid()/auth.role(), managed roles, PostgREST, and Storage.

The initial migration seeds module keys core, hse, and operations. Operations has a registry row, but no Operations business tables or implemented Operations workflow.

## Domain coverage matrix

Statuses are about evidence in this repository. Implemented means a relational representation and meaningful database controls exist; it does not mean the complete UI, API, deployment, and operations workflow is live.

### A. Platform core

| Capability | Status | Evidence and limitation |
|---|---|---|
| Tenant/company identity | Implemented | core.tenants has name, optional industry label, active/suspended/closed lifecycle, creator and timestamp. Tenant-owned core/HSE/IAM rows use tenant identifiers. No general settings entity. |
| Tenant lifecycle and company settings | Partially implemented | Tenant and site status exist, and memberships have status. Company settings beyond name/industry and structure are absent; no closure workflow, retention/export policy, tenant-specific feature config, or setting history. |
| Company domains | Partially implemented | core.tenant_domains has unique normalized name and pending/verified/disabled states with verified_at consistency. No DNS challenge/token, verification evidence, domain claim workflow, or Auth domain integration. |
| Organization units and sites | Implemented for access structure | core.org_units is a tenant-scoped self-referencing hierarchy; core.sites belongs to a tenant and optionally one org unit, with tenant-unique code. There is no automatic descendant-scope inheritance. These are not HR departments/positions. |
| Module catalog and lifecycle | Partially implemented | core.modules stores key/label/enabled. Registry is seeded with Core, HSE, Operations. No semantic version, dependencies, migration compatibility, rollout state, tenant configuration, or module-specific service registration. |
| Module entitlements | Implemented at company scope | subscriptions and company-scoped grants can confer module entitlement. private.has_module_entitlement requires active tenant/module and current grant or active plan/item. Membership-specific module grants are intentionally not an authorization mechanism; the agreed contract keeps modules tenant-wide. The RPC/API should reject a member-scoped module grant instead of silently accepting a no-op (F-02). |
| Feature entitlements | Implemented with company and member exceptions | Plan feature entitlements and exception grants support tenant or membership scope; feature access also requires the parent module. This meets the current commercial contract. |
| Plans, subscriptions and entitlements | Implemented for internal SaaS entitlement ledger | Normalized plan, plan entitlement, subscription, item, grant, status, period, quota and price snapshots exist. Draft unpriced HSE base plan is seeded. This is SENTRIQ’s own customer licensing, not a tenant’s ERP finance model. |
| Billing treatment and exceptions | Partially implemented | Grant billing treatment distinguishes tenant billable, complimentary and platform absorbed. Billable exceptions require same tenant as payer. No payment processor, tax engine, credit note, refund/reconciliation workflow, external webhook verification or billing-account hierarchy. |
| Usage metering | Partially implemented | core.usage_events is immutable, tenant/idempotency constrained, and stabilization documents concurrency-safe quota and exact replay semantics. Metadata is an object with sensitive-key screening. Retention, correction/adjustment, reconciliation, export, aggregation and high-volume partition/archive strategy are not defined. |
| Invoices and payments | Partially implemented; platform billing only | core.invoices/items/payments cover SENTRIQ subscriptions/features, totals, source references and external provider references. Payment provider integration, verified webhooks, tax jurisdictions, credit/refund accounting, collection/dunning and reconciliation are absent. Not customer Accounts Payable/Receivable. |
| Tenant configuration | Missing beyond a few profile fields | There is no tenant setting/key-value or typed configuration model. Avoid adding a generic JSONB settings bag before the required settings, validation, precedence and audit rules are known. |
| Product module and feature lifecycle | Partially implemented | Enabled flags and entitlement checks are present. No product release/compatibility metadata, dependency graph, rollout cohort, regional availability or module configuration lifecycle. |

### B. Identity, organization and authorization

| Capability | Status | Evidence and limitation |
|---|---|---|
| Shared identity | Implemented as Supabase integration | Auth identity is external auth.users and referenced by memberships/operators/actors. Database does not own passwords or a separate person identity. Identity provider choice in ADR 0001 remains proposed/awaiting owner approval. |
| Platform Owner/Subowner | Implemented with a narrow database lifecycle | iam.platform_operators is separate from company membership; unique active Owner; api.manage_subowner gates roster changes on Owner identity. Only Owner has the management RPC. Bootstrap is an out-of-band postgres install operation; its SECURITY DEFINER current_user check does not prove caller identity (P-02), so ACL is the boundary. |
| Company Superadmin/Admin/Employee | Partially implemented | iam.memberships.member_role defines company_superadmin/company_admin/employee and status. Management role is separate from functional roles. F-01 is confirmed: authenticated company management policies permit direct active membership insertion and status activation without verified invite acceptance. |
| Membership lifecycle and invitations | Partially implemented | Invitations store only token hash and validate expiry, one-use acceptance, and verified matching Auth email in service-only RPCs. Company invites cannot create Superadmins. Direct table write paths still allow lifecycle bypass; no email delivery or application API exists. Reactivation clears old authorization rows as recorded in stabilization. |
| Functional roles | Implemented | iam.roles, role_permissions, membership_roles, membership_role_sites and membership_role_org_units separate reusable function privileges from management authority, with start/end/revoke data and tenant validation. Protected system role data cannot be tenant-edited. |
| Permission catalog and direct grants | Implemented with lifecycle gaps | permission_catalog, role_permissions and member_permissions represent read/write permissions. Catalog entries include HSE and core structure permissions. Direct grants have active state but lack temporal validity and immutable grant/revoke events. The catalog is currently small and HSE-biased. |
| Membership-role assignment | Implemented | Assignment supports start/end/revoke, tenant-qualified membership, single active assignment per role/member, actor fields and scope bindings. Audit trigger records selected changes. |
| Site and org-unit scope | Implemented with strict intersection | site_access and org_unit_access are membership scopes; role assignment can additionally bind to site/org unit. Authorization requires the relevant access and matching scope. Org-unit descendants do not inherit; make this an explicit product rule. |
| Task-level assignment | Partially implemented, HSE-specific | iam.task_assignments supports inspection/review/finding/action/follow_up and stores tenant/site/org. Trigger resolves the target and rejects mismatch. It is not a generic task engine and uses polymorphic task_id rather than database FKs to five tables. Assignment does not add permission and must retain module, permission, site and org checks. |
| Effective permission resolution | Implemented in SQL for the current HSE/core paths | private.can_access_hse and private.has_hse_permission combine membership, tenant, HSE module, permission, site/org scope and validated task assignment. Company Superadmin is an HSE functional shortcut, still subject to membership/tenant/module lifecycle. Core helper currently reuses this permission resolver. A reusable module-neutral authorization contract/API service has not yet been implemented. |
| Delegation and temporary access | Partially implemented | Role assignments and role-scope bindings have starts/ends and revocation. Direct grants, site/org access and task assignments do not consistently carry expiration, delegated-by, approval or reason history. No approval-to-delegate model. |
| Permission history and revocation | Partially implemented | Audit triggers and revocation timestamps exist on role assignments and role-scope bindings. Some direct grants/access records use mutable active flags, not append-only grant/revoke histories. Retention and actor attribution are incomplete at service boundary. |
| Management authority vs functional roles | Implemented as an important separation | Management level lives on membership; Owner/Subowner lives in platform_operators; assignable roles are functional. Trigger logic prevents functional permissions granting membership/role/permission/scope/operator/billing management. This must stay invariant in every future module. |
| MFA/step-up | Missing from database and unverified in app | No migration checks JWT AAL/MFA claims. Existing security review P-03 requires hosted Auth/Laravel step-up controls for Owner/Subowner and sensitive actions before production. |
| Service identity and actor provenance | Missing from repository integration | RPCs accept actor UUIDs from a service_role path. The database can validate referenced users and current membership, but cannot prove an HTTP caller is that user when the service role bypasses RLS. Laravel/API must bind actor IDs to verified Supabase claims; the service/job actor should be recorded separately. |

### C. HSE

| Capability | Status | Evidence and limitation |
|---|---|---|
| Dynamic forms | JSONB/generic representation | form_templates.title and definition are JSONB objects. This is appropriate for tenant-authored field definitions and bilingual content, but database checks only require JSON object type; no versioned schema validator checks field keys/types/conditions/repeat groups/scoring. |
| Published form version/history | Implemented, JSON snapshot | form_versions has tenant/template/version uniqueness and JSONB snapshot; inspections pin a specific version. Immutable trigger protects published versions. Database type-checks shape but does not validate snapshot compatibility or preserve every authoring edit as a version. |
| Inspections | Implemented core workflow | Tenant/site/template/version/inspector FKs, status/current_stage, answers JSON array, revision, submitted time and optimistic transition guards. Answers are not validated against pinned JSON form version. No due/scheduled/recurrent instance, calendar/timezone, cancellation reason, or explicit assignee history. |
| Assignment and review stages | Partially implemented | Task assignments can bind inspection/review. Reviews are append-only and fixed to reviewer_1, reviewer_2, final_reviewer with approved/returned outcome. No configurable stage count, SLA, escalation, substitute/delegation, quorum or workflow revision. |
| Findings/observations | Partially implemented | hse.findings ties each record to an inspection/question and site, with priority and state. It is not a stand-alone observation/incident/hazard register and lacks classification taxonomy, discovered-at/source, risk rating, affected persons and closure verification fields. |
| Incidents and near misses | Missing | No incident record, occurrence/location/time, injury/illness/damage, people involved, regulator reporting, investigation, root cause, severity, or near-miss lifecycle. A finding created from an inspection cannot substitute because its mandatory parent inspection and question ID lose incident-specific semantics. |
| Hazard identification/reporting | Missing as a lifecycle domain | No hazard register, reports, source, exposure/population, owner, severity/likelihood, risk score, review state or change history. A form answer or finding can capture an isolated observation but cannot provide a queryable current hazard and lifecycle relationships. |
| Risk assessments/registers | Missing | No risk assessment, assessment version, matrix scale, inherent/residual risk, risk owner, review date, linked controls or acceptance decision. |
| Control measures | Missing | No control catalogue, hierarchy-of-controls classification, owner, effectiveness check, due date or link from a risk/incident/work activity. |
| Corrective/preventive actions | Partially implemented | corrective_actions links to a finding and inspection, owner, priority, statuses, revision and due-date fields. action_updates records append-only status/comment, and follow_ups represents due verification work. No preventive-action classification, root-cause/cause analysis, separate action plan/evidence, verified effectiveness, formal closure approval configuration or risk linkage. |
| Follow-up and verification | Partially implemented | follow_ups have owner, due date, status/outcome and action FK. No separate verifier, verification result/evidence lifecycle, overdue/escalation event or reusable follow-up entity. |
| Permit to Work | Missing | No permit, work scope, hazard/control checklist, isolation/LOTO, validity window, issuer/acceptor, work party, suspensions, handback, extension or linked asset/location. |
| Toolbox Talks | Missing | No talk/session, topic/version, presenter, attendance acknowledgements, questions, evidence or re-delivery lifecycle. |
| HSE training/competency | Missing | No course, competency, qualification, person credential, issue/expiry, assessment or worker qualification record. Access membership is not an employee/training profile. |
| HSE audits/compliance obligations | Missing | audit.events is a technical change ledger, not an HSE audit program. No obligation/source/regulation, audit plan, checklist instance, evidence, nonconformance, reviewer or corrective action linkage. |
| Emergency preparedness/drills | Missing | No scenario, emergency plan/version, participants/roles, drill schedule, observation, response time, after-action report or corrective action. |
| Contractor safety | Missing | No contractor organization, external worker/person, onboarding, insurance/qualification, site induction, permit, access window or sponsor. |
| Evidence/document management | Partially implemented, HSE-specific | evidence_files carries metadata and one of four link types; private Storage bucket uses tenant/site object prefixes and policy joins metadata. No file version, hash, malware scan state, retention/legal hold, document classification, reusable document library or all-module document service. |
| HSE reporting/analytics | Partially represented by lookup indexes | Status/owner/site/due date indexes support operational filtering. No reporting definitions, snapshots, exports, aggregate model, BI warehouse, or analytics privacy policy. |
| Workflow and audit history | Partially implemented | Inspection transitions are guarded; reviews/action updates/form versions/audit are append-only. There is no generic workflow engine or event-sourced model. |

### D. Shared enterprise services

| Capability | Status | Evidence and limitation |
|---|---|---|
| Workflow engine | Missing as a shared service | Only HSE inspection transitions are guarded by HSE-specific triggers. Keep that module-specific until at least a second domain shares real, stable requirements. |
| Approval chains and history | Partially implemented | Inspection review history exists with three hard-coded stages. It is not a reusable approval chain for purchasing, HR, finance, or other modules. |
| Business rules | Missing as a generic engine | Permission catalogs and product entitlement configuration exist, but they are not a tenant business-rule engine. No rule version, evaluator, condition schema or test harness. |
| Notifications and delivery history | Missing | No recipient, notification event, channel, delivery attempt, retry/dead-letter or preference model. Invitation email is a future server/provider integration. |
| Tasks and assignments | Partially implemented | HSE security assignment exists, not a first-class work queue with title, due date, priority, lifecycle, source, completion and history across modules. |
| Comments/activity timeline | Partially implemented | HSE action_updates and inspection review reason exist. No cross-domain activity feed or shared comment stream. |
| Documents/evidence | Partially implemented | Evidence metadata and Storage path are HSE-bound. No shared document and version boundary. |
| Audit events/business history | Partially implemented | audit.events is append-only and selected row-change triggers write allowlisted changed-field diffs for app tables. It does not cover Auth/Storage provider events or all external business effects, and a logged diff is not a domain event stream or compliance archive. Audit IDs are bigint while generic record_id is UUID, so non-UUID targets require a separate strategy. |
| Tenant configuration/custom fields | Missing | No typed settings registry, scoped configuration/version, custom-field definitions or validation. Avoid an unrestricted JSONB configuration table. |
| Reporting definitions/snapshots/exports | Missing | No saved report model, access-filtered snapshot, export job, expiration or audit linkage. |
| Integration endpoints/external identifiers | Missing | Provider references exist on payments only. No external entity mapping, connector credentials reference, sync cursor or reconciliation state. Secrets must remain in a secret manager, not database JSON. |
| Webhooks and delivery retries | Missing | No registered endpoint, subscribed event catalog, signing secret reference, delivery attempt or retry/dead-letter ledger. |
| Background jobs and idempotency | Partially implemented for billing operations | Usage, invoice and invitation critical paths have idempotency/concurrency controls in stabilization. No generic job/run/attempt/lease/cancellation/dead-letter model. |

### E. Future ERP modules

| Module/domain | Status | Evidence and why it is not implemented |
|---|---|---|
| HR | Future scope | No employee/person, employment history, position, contract, leave, attendance, qualification/competency or contractor worker tables. Membership is an access relationship, not an employment record. Organization units are a generic tenant tree, not a full department/position model. HSE training should link to a shared person/worker record after identity requirements are decided. |
| Operations | Future scope | core.modules contains an enabled Operations registry entry and iam.task_assignments recognizes HSE task kinds only. No work order, maintenance request, operational checklist, shift, production/service operation, work center or operational event entities. |
| Assets | Future scope | No asset register, category, custody, location history, maintenance, inspection lifecycle or asset identity. HSE inspection can be associated only with a site, not an asset. |
| Procurement | Future scope | No supplier, requisition, purchase order, supplier contract, approval, goods receipt or sourcing lifecycle. |
| Inventory | Future scope | No item/SKU, unit conversion, warehouse/bin, balance, reservation, movement, transfer, count or adjustment ledger. |
| Finance | Future scope | Core invoices/payments settle SENTRIQ commercial subscriptions. No customer chart of accounts, journal/ledger, AP/AR, tax, cost center, period close, allocation or reconciliation. It would be unsafe to treat core.invoices as customer finance. |

## Data model quality review

### Strengths

- Data is separated into core, iam, hse and audit schemas. Platform-level operators are not company memberships.
- Tenant IDs appear in business tables and important composite FKs bind child records to the same tenant. HSE actions also enforce that a finding and inspection agree on tenant, site and inspection.
- Lookup catalogs and commercial entities are normalized; invoices and line items, subscriptions and items, plans and entitlements, roles and permissions are separate rows.
- Published HSE form snapshots are separate from mutable form templates, and inspections reference the exact form version.
- Status values and positive quantities/rates use CHECK constraints. Unique constraints encode tenant codes, role keys, invitation uniqueness, idempotency, and commercial invariants.
- Stabilization introduced controlled lifecycle transitions, append-only histories for critical HSE/commercial rows, serialized invitation acceptance, usage idempotency and concurrency controls.

### Risks and trade-offs

- JSONB is constrained only by top-level type on forms, answers, usage metadata, payments, invoice metadata and audit summary. It is appropriate for extensible form definitions and immutable snapshots, but operational query facts must be promoted into typed columns/child relations where filtering, reporting, joining or enforcing correctness is important.
- Form definition and answer JSON have no database-validated schema contract or version-aware answer checker. Invalid answer keys, missing required answers, incompatible field types, and stale clients can persist while satisfying the JSON array check.
- hse.evidence_files and iam.task_assignments use polymorphic targets. Triggers validate the current small list of targets, but the database cannot express normal FK cascade/restrict semantics for each target. Every new target requires coordinated trigger, RLS, path, API and test changes. Keep these deliberately bounded; do not turn them into untyped generic document/task stores.
- iam.memberships combines tenant access lifecycle, management level and basic display contact fields. This is acceptable for the current access foundation, but employee/person/employment semantics belong in a future people domain with explicit relationship to membership, not by overloading membership.
- core.entitlement_grants carries module-versus-feature target and billing override fields. Its one-of check, tenant/module/feature FKs and commercial lifecycle make it workable for current scope. Split grant subtypes only if distinct lifecycle, auditing or query semantics appear.
- tenant_domains has a verification state but no actual proof/challenge record or method. A “verified” row’s evidence currently depends on trusted service logic not in this repository.
- Soft lifecycle is generally represented by status/active/revocation; physical deletion is restricted/revoked for browser roles. Retention duration, anonymization, right-to-erasure, closure, archival, and legal hold are not defined.
- Audit row triggers write selected allowlisted diffs. Actor identity is auth.uid() context; trusted service callers and jobs must supply trustworthy attribution. Audit summary growth, tenant partitioning/retention, tamper-evidence externalization, and privacy redaction need product/compliance requirements.
- The documented indexes serve known HSE status/site/owner/due-date queries. There are no JSONB GIN indexes or analytical indexes; do not add them until query plans and API workload are known. Large usage_events/audit.events need a retention and partitioning decision before scale.
- Unique and FK constraints cover many tenant boundaries, but not every FK is tenant-composite by design. Cross-tenant validation should remain explicit for every newly tenant-owned reference. Supabase Auth is a shared global identity, intentionally not tenant-owned.
- Current HSE transaction model is relational OLTP, not event sourcing. Append-only review/action/audit records preserve selected history, but mutable current rows remain the source for current status.
- No app-owned table partitioning, reporting replica, outbox, generic job table or archival plan exists. Large-table strategy must be driven by customer volume and retention requirements.

### Avoid adding tables prematurely

Do not create separate lookup tables for every CHECK-constrained status/priority when the vocabulary is stable and module-owned. Do not normalize every label or answer field in a tenant-defined form into columns. Keep HSE workflow-specific history in module tables unless a second domain proves a shared abstraction. Avoid a generic JSONB task, workflow, business-rule, custom-field or document table until tenant isolation, lifecycle, querying, retention and domain ownership are concrete.

## Authorization coverage and security assessment

The intended allow decision is:

~~~text
verified identity
  ∩ active tenant membership
  ∩ active tenant
  ∩ company-level module entitlement
  ∩ feature entitlement when the feature is gated
  ∩ functional permission
  ∩ site access and matching site/org-unit scope
  ∩ task assignment for task-bound operations
  ∩ business lifecycle and workflow rules
~~~

For the current HSE path, migrations express active membership/tenant, HSE module, functional permission, scope, task assignment and workflow checks in SQL/RLS. A feature-specific operation also needs feature entitlement. Modules remain company-level. Membership exceptions are feature-only. Task assignment is not itself a permission and must not widen site/org access.

| Security concern | Assessment |
|---|---|
| Cross-tenant row reads/writes | Strong database foundation: all 39 app tables were recorded RLS-enabled and forced; composite tenant FKs are used heavily; prior negative probes denied selected cross-tenant access. Do not generalize selected probe coverage to every table/write/API path. |
| Direct management of membership lifecycle | Confirmed gap F-01. Active tenant managers can insert active employee/company-admin membership or activate membership rows without the invitee accepting a verified-email invitation. This defeats mailbox acceptance. |
| Module/member scope mismatch | F-02: the grant RPC accepts member-scoped module grant, but module evaluator is tenant-only. Membership-level module exception must not be permitted by the agreed contract; reject it at the command boundary. Feature exceptions may be membership-specific and remain under the parent module. |
| Superadmin functional shortcut | Company Superadmin has an HSE permission shortcut after active membership/tenant and module entitlement. This is a deliberate management-level policy. It should be approved and exposed in an auditable effective-access explanation. |
| Task boundary | Database validator ties allowed HSE task IDs to tenant/site/org. Permission evaluation additionally requires site access and a functional permission. Future task kinds must not be added without equivalent target resolution and negative tests. |
| Privileged server operations | Service-role RPCs bypass RLS. Current database body and ACLs provide guards, but actor UUID provenance depends on trusted future Laravel/API code (P-01). Never accept actor/user IDs from browser request payloads. |
| Platform MFA | No AAL/step-up guard appears in migrations (P-03). Require strong Auth/Laravel step-up for owner/subowner and high-impact grants before production. |
| Function ACL default | Existing 47 SECURITY DEFINER functions are recorded as postgres-owned with empty search_path and no PUBLIC/anon execute; no default ACL hardening exists for future functions (P-05). Add safe default function privileges as a later security remediation, then grant explicitly per RPC. |
| Storage | Private bucket and row policy join tenant/site object prefix to HSE metadata and permission. Existing review tested storage.objects row policy, not HTTP upload/download, signed URL lifetime/revocation or provider operations. |
| Domain verification | The database can hold verified status but cannot itself demonstrate domain ownership; proof verification is a trusted service requirement. |
| Direct database connections | A custom GUC/JWT-shaped setting set by a direct client is not an authentication secret. Laravel must use verified token context and non-BYPASSRLS user queries; pooled identity must be transaction-local and cleared. |
| Authorization parity | No Laravel AccessResolver exists in this repository. Implement PHP action checks and SQL/RLS invariants from one vocabulary and shared allow/deny vectors; frontend hiding is never authorization. |

### Existing security-review findings retained

- F-01 Medium, confirmed: company manager can directly activate membership without verified invitation acceptance.
- F-02 Low, confirmed behavior mismatch: a membership-scoped module grant is accepted but does not authorize module access. Contract requires rejecting that scope; only features can have membership-specific grants.
- F-03 Low, confirmed: local concurrency harness persists fixtures that make repeat pgTAP runs fail on a shared local stack. Current GitHub workflow disposes its stack. Fix test hygiene before relying on repeat local runs.
- P-01 actor UUID provenance is a future-server obligation.
- P-02 SECURITY DEFINER current_user in bootstrap reflects function owner, not invoker; ACL is the control.
- P-03 no database/application MFA/AAL evidence.
- P-04 future-start active subscription can reserve the live slot even before entitlement start; confirm scheduled-subscription semantics.
- P-05 no default function ACL hardening for future SECURITY DEFINER functions.

This audit preserves the review as evidence and does not claim these findings are remediated.

## Current-state ERD

The current ERDs below show all 39 application tables, grouped for readability. They focus on tenant-bearing business relationships and omit repeated auth-user, creator/grantor, and some non-tenant lookup links from the lines to keep diagrams readable. The migrations have 115 total FK constraints; see the table catalog above and migration source for the complete constraint definitions.

### Core and commercial entities — 16 tables

~~~mermaid
erDiagram
  TENANTS {
    uuid id PK
  }
  ORG_UNITS {
    uuid id PK
    uuid tenant_id FK
    uuid parent_id FK
  }
  SITES {
    uuid id PK
    uuid tenant_id FK
    uuid org_unit_id FK
  }
  TENANT_DOMAINS {
    uuid id PK
    uuid tenant_id FK
  }
  MODULES {
    text module_key PK
  }
  TENANT_ENTITLEMENTS {
    uuid id PK
    uuid tenant_id FK
    text module_key FK
  }
  FEATURES {
    text feature_key PK
    text module_key FK
  }
  PLANS {
    uuid id PK
  }
  PLAN_ENTITLEMENTS {
    uuid id PK
    uuid plan_id FK
    text module_key FK
    text feature_key FK
  }
  SUBSCRIPTIONS {
    uuid id PK
    uuid tenant_id FK
    uuid plan_id FK
  }
  SUBSCRIPTION_ITEMS {
    uuid id PK
    uuid tenant_id FK
    uuid subscription_id FK
    uuid plan_entitlement_id FK
  }
  ENTITLEMENT_GRANTS {
    uuid id PK
    uuid tenant_id FK
    uuid membership_id FK
    text module_key FK
    text feature_key FK
  }
  USAGE_EVENTS {
    uuid id PK
    uuid tenant_id FK
    uuid beneficiary_membership_id FK
    text feature_key FK
    uuid grant_id FK
  }
  INVOICES {
    uuid id PK
    uuid tenant_id FK
  }
  INVOICE_ITEMS {
    uuid id PK
    uuid tenant_id FK
    uuid invoice_id FK
    uuid usage_event_id FK
    uuid grant_id FK
    uuid subscription_item_id FK
  }
  PAYMENTS {
    uuid id PK
    uuid tenant_id FK
    uuid invoice_id FK
  }

  TENANTS ||--o{ ORG_UNITS : owns
  ORG_UNITS o|--o{ ORG_UNITS : parent
  TENANTS ||--o{ SITES : owns
  ORG_UNITS o|--o{ SITES : contains
  TENANTS ||--o{ TENANT_DOMAINS : claims
  MODULES ||--o{ TENANT_ENTITLEMENTS : legacy_switch
  MODULES ||--o{ FEATURES : contains
  PLANS ||--o{ PLAN_ENTITLEMENTS : defines
  MODULES o|--o{ PLAN_ENTITLEMENTS : grants
  FEATURES o|--o{ PLAN_ENTITLEMENTS : grants
  TENANTS ||--o{ SUBSCRIPTIONS : subscribes
  PLANS ||--o{ SUBSCRIPTIONS : selected
  SUBSCRIPTIONS ||--o{ SUBSCRIPTION_ITEMS : contains
  PLAN_ENTITLEMENTS ||--o{ SUBSCRIPTION_ITEMS : prices
  TENANTS ||--o{ ENTITLEMENT_GRANTS : owns
  MODULES o|--o{ ENTITLEMENT_GRANTS : grants
  FEATURES o|--o{ ENTITLEMENT_GRANTS : grants
  TENANTS ||--o{ USAGE_EVENTS : meters
  FEATURES ||--o{ USAGE_EVENTS : measures
  TENANTS ||--o{ INVOICES : billed
  INVOICES ||--o{ INVOICE_ITEMS : lists
  USAGE_EVENTS o|--o| INVOICE_ITEMS : billed_once
  INVOICES ||--o{ PAYMENTS : receives
~~~

### Identity, authorization and platform operators — 13 tables

~~~mermaid
erDiagram
  AUTH_USERS {
    uuid id PK
  }
  PLATFORM_OPERATORS {
    uuid user_id PK FK
    text operator_role
  }
  TENANTS {
    uuid id PK
  }
  MEMBERSHIPS {
    uuid id PK
    uuid tenant_id FK
    uuid user_id FK
    text member_role
    text status
  }
  INVITATIONS {
    uuid id PK
    uuid tenant_id FK
    text email
    bytea token_hash
  }
  SITES {
    uuid id PK
    uuid tenant_id FK
  }
  ORG_UNITS {
    uuid id PK
    uuid tenant_id FK
  }
  PERMISSION_CATALOG {
    text permission_key PK
    text module_key
  }
  ROLES {
    uuid id PK
    uuid tenant_id FK
    text role_key
  }
  ROLE_PERMISSIONS {
    uuid role_id PK,FK
    text permission_key PK,FK
    text scope_kind
  }
  MEMBERSHIP_ROLES {
    uuid id PK
    uuid tenant_id FK
    uuid membership_id FK
    uuid role_id FK
  }
  MEMBERSHIP_ROLE_SITES {
    uuid id PK
    uuid tenant_id FK
    uuid membership_role_id FK
    uuid site_id FK
  }
  MEMBERSHIP_ROLE_ORG_UNITS {
    uuid id PK
    uuid tenant_id FK
    uuid membership_role_id FK
    uuid org_unit_id FK
  }
  MEMBER_PERMISSIONS {
    uuid id PK
    uuid tenant_id FK
    uuid membership_id FK
    text permission_key FK
  }
  SITE_ACCESS {
    uuid tenant_id PK,FK
    uuid membership_id PK,FK
    uuid site_id PK,FK
  }
  ORG_UNIT_ACCESS {
    uuid tenant_id PK,FK
    uuid membership_id PK,FK
    uuid org_unit_id PK,FK
  }
  TASK_ASSIGNMENTS {
    uuid id PK
    uuid tenant_id FK
    uuid membership_id FK
    text task_kind
    uuid task_id
  }

  AUTH_USERS ||--o| PLATFORM_OPERATORS : operator_identity
  AUTH_USERS ||--o{ MEMBERSHIPS : joins
  TENANTS ||--o{ MEMBERSHIPS : contains
  TENANTS ||--o{ INVITATIONS : invites
  TENANTS ||--o{ ROLES : defines
  ROLES ||--o{ ROLE_PERMISSIONS : grants
  MEMBERSHIPS ||--o{ MEMBERSHIP_ROLES : assigned
  ROLES ||--o{ MEMBERSHIP_ROLES : used_by
  MEMBERSHIP_ROLES ||--o{ MEMBERSHIP_ROLE_SITES : bound_to
  MEMBERSHIP_ROLES ||--o{ MEMBERSHIP_ROLE_ORG_UNITS : bound_to
  MEMBERSHIPS ||--o{ MEMBER_PERMISSIONS : direct_grant
  PERMISSION_CATALOG ||--o{ MEMBER_PERMISSIONS : defines
  MEMBERSHIPS ||--o{ SITE_ACCESS : scoped
  SITES ||--o{ SITE_ACCESS : permits
  MEMBERSHIPS ||--o{ ORG_UNIT_ACCESS : scoped
  ORG_UNITS ||--o{ ORG_UNIT_ACCESS : permits
  MEMBERSHIPS ||--o{ TASK_ASSIGNMENTS : assigned
~~~

The last diagram includes external auth.users as an integration entity, not one of the 39 app-owned tables. Role-to-permission key and task-kind/task-id edges are validated through lookup constraints and trigger logic. Task target is polymorphic across the five HSE task kinds.

### HSE and audit entities — 10 tables

~~~mermaid
erDiagram
  TENANTS {
    uuid id PK
  }
  SITES {
    uuid id PK
    uuid tenant_id FK
  }
  MEMBERSHIPS {
    uuid id PK
    uuid tenant_id FK
  }
  FORM_TEMPLATES {
    uuid id PK
    uuid tenant_id FK
    jsonb definition
  }
  FORM_VERSIONS {
    uuid id PK
    uuid tenant_id FK
    uuid template_id FK
    jsonb snapshot
  }
  INSPECTIONS {
    uuid id PK
    uuid tenant_id FK
    uuid site_id FK
    uuid template_id FK
    uuid form_version_id FK
    jsonb answers
  }
  INSPECTION_REVIEWS {
    uuid id PK
    uuid tenant_id FK
    uuid inspection_id FK
    text stage
    uuid actor_membership_id FK
  }
  FINDINGS {
    uuid id PK
    uuid tenant_id FK
    uuid inspection_id FK
    uuid site_id FK
  }
  CORRECTIVE_ACTIONS {
    uuid id PK
    uuid tenant_id FK
    uuid finding_id FK
    uuid inspection_id FK
    uuid owner_membership_id FK
  }
  ACTION_UPDATES {
    uuid id PK
    uuid tenant_id FK
    uuid action_id FK
    uuid actor_membership_id FK
  }
  FOLLOW_UPS {
    uuid id PK
    uuid tenant_id FK
    uuid action_id FK
    uuid owner_membership_id FK
  }
  EVIDENCE_FILES {
    uuid id PK
    uuid tenant_id FK
    uuid site_id FK
    text linked_record_type
    uuid linked_record_id
  }
  AUDIT_EVENTS {
    bigint id PK
    uuid tenant_id FK
    uuid actor_membership_id FK
    jsonb summary
  }

  TENANTS ||--o{ FORM_TEMPLATES : owns
  FORM_TEMPLATES ||--o{ FORM_VERSIONS : versions
  FORM_TEMPLATES ||--o{ INSPECTIONS : instantiates
  FORM_VERSIONS ||--o{ INSPECTIONS : pins
  SITES ||--o{ INSPECTIONS : locates
  MEMBERSHIPS ||--o{ INSPECTIONS : inspected_by
  INSPECTIONS ||--o{ INSPECTION_REVIEWS : reviewed
  INSPECTIONS ||--o{ FINDINGS : identifies
  FINDINGS ||--o{ CORRECTIVE_ACTIONS : addressed_by
  CORRECTIVE_ACTIONS ||--o{ ACTION_UPDATES : history
  CORRECTIVE_ACTIONS ||--o{ FOLLOW_UPS : verified_by
  TENANTS ||--o{ EVIDENCE_FILES : owns
  AUDIT_EVENTS }o--o| TENANTS : scoped_to
~~~

Evidence target links are validated by a trigger to inspection/finding/action/follow_up and tenant/site consistency, not FK edges. Storage bytes are external to this application ERD.

## Audit scope boundary

At audit baseline commit `31368375fa4c4fcafd9f5a6d2078b2dc79ced854`, the `codex/schema-coverage-audit` branch added architecture and domain documentation only; that audit commit did not change migrations, policies, functions, grants, tests, application code, Supabase configuration, hosted databases, or production systems. The follow-up branch and its database changes are documented above and in `REMEDIATION_RESULTS.md`. No schema redesign or ERP implementation is being proposed as completed work.
