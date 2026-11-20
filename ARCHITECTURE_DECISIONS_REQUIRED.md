# SENTRIQ Architecture Decisions Required

## Decision record status

This list separates implementation findings from unresolved product/architecture choices. The three existing ADRs—identity, authorization/RLS, and evidence storage/scope—are marked PROPOSED and awaiting owner approval. The recommendations below are design guidance; they do not change current migration behavior. Security defects already confirmed in SECURITY_REVIEW.md require remediation regardless of product preference.

Each decision calls out the product-owner approval point. Security controls must be implemented in the trusted application/API and PostgreSQL/RLS layers; frontend-only decisions are not security boundaries.

## D-01 — Identity provider and trusted application request path

**Question:** Will Supabase Auth remain the identity provider for initial HSE, and will Laravel validate Supabase tokens and serve as the trusted application/API layer?

**Options:**

- **A. Supabase Auth plus Laravel validation (recommended for initial HSE).** Advantages: matches auth.users FKs, auth.uid() policies and current migrations; lowest migration surface; managed confirmation and recovery. Disadvantages: vendor dependency and JWT/session integration obligations.
- **B. Laravel-managed identity or another IdP before launch.** Advantages: may align with enterprise SSO or hosting requirements. Disadvantages: replaces identity FKs/claims/invites and requires a trusted transaction context plus account migration plan; significantly expands launch scope.

**Security impact:** A direct DB client can set request-like GUC values; they are not credentials. User requests must carry verified Auth identity through a non-BYPASSRLS path. Service-role keys remain server-only.

**Data-model impact:** Option A preserves auth.users and auth.uid() references. Option B requires identity mapping/cutover and updated RLS helpers, actor fields, invitation acceptance and tests.

**Recommendation:** Select A for initial HSE and keep an identity adapter boundary in Laravel. Revisit only with a specific SSO, residency, portability or cost requirement.

**Product owner approval:** Approve identity provider, token/session lifecycle, API responsibility and whether SSO is a launch requirement. ADR 0001 awaits this decision.

## D-02 — Membership activation must require verified invitation acceptance

**Question:** Which single trusted path activates a Company Admin or Employee membership?

**Options:**

- **A. Revoke authenticated direct INSERT and sensitive status/role/email updates; use narrow provisioning and acceptance RPCs (recommended).** Advantages: preserves verified-email and one-use invitation controls; leaves an auditable lifecycle. Disadvantages: requires Laravel/server integration and carefully constrained service RPCs.
- **B. Allow a Company Superadmin to create active memberships directly.** Advantages: simpler bulk provisioning. Disadvantages: current F-01 demonstrates that this bypasses mailbox proof and the invitation acceptance audit; creates immediate tenant access.

**Security impact:** F-01 is a confirmed Medium finding. A manager can attach an existing Auth UUID or activate an invited membership without the target proving control of its verified email.

**Data-model impact:** Keep invitations as hashed, expiring, one-use records. Add narrowly scoped server-mediated provisioning only if bulk onboarding is required; record which path, who initiated it and how identity was verified.

**Recommendation:** A. This is a pre-onboarding security remediation, not an optional product preference. Bulk import can create pending invitations and require normal acceptance.

**Implementation status:** The follow-up database migration has revoked direct membership writes and added a service-only suspend/end RPC; it cannot activate or alter identity/management level. Ordinary membership activation requires verified invitation acceptance. The historical F-01 evidence above describes the audit baseline. Trusted Laravel actor provenance remains a production gate.

**Product owner approval:** Approve whether invitations are the only activation path and whether a bulk importer may create pending, never active, memberships.

## D-03 — Management authority and Company Admin delegation

**Question:** Which company-level functions may the Superadmin open to a Company Admin, and which must remain exclusive to the Superadmin?

**Options:**

- **A. Preserve the current boundary: Superadmin owns membership/role/scope/configuration management; Admin receives selected functional operations only (recommended until use cases are approved).** Advantages: keeps privilege review narrow and supports existing role/permission separation. Disadvantages: may require the Superadmin to handle operational administration.
- **B. Allow the Superadmin to delegate named administrative capabilities.** Advantages: supports larger organizations. Disadvantages: higher risk of privilege escalation and more complex approval/revocation history.
- **C. Let a functional role confer management actions.** Advantages: fewer concepts in UI. Disadvantages: directly violates the established authority separation and is not recommended.

**Security impact:** Management actions should be separately named, tenant-scoped and guarded. A functional HSE permission must not add/remove members, roles, scopes, domains or entitlements.

**Data-model impact:** Current member_role handles levels; functional roles are separate. Delegation would need an explicit admin-capability grant with target, approver, validity, reason, history and effective-access query—not a role label alias.

**Recommendation:** A for initial release. Add B only from a reviewed management-action matrix.

**Product owner approval:** Approve the explicit operation list for Superadmin, Admin and Employee, including who can invite, suspend/reactivate, assign roles, assign sites/org units and manage forms.

## D-04 — Module and feature exception contract

**Question:** Should membership-specific commercial exceptions apply to modules or only to features?

**Options:**

- **A. Company-level modules; feature grants may be tenant-wide or membership-specific (recommended and aligned with the brief).** Advantages: one company has a consistent module boundary while a purchased/special feature can be narrowly assigned. Disadvantages: cannot buy module access for a lone employee without enabling the company module.
- **B. Membership-scoped module grants.** Advantages: supports individual module access. Disadvantages: conflicts with the current accepted contract and creates ambiguous company/module availability.

**Security impact:** A feature exception must still require its parent module and active tenant/member. Feature grants must never bypass the permission or data scope.

**Data-model impact:** Current private.has_module_entitlement is tenant-only, while feature evaluation accepts optional membership scope. Current issue_entitlement_grant accepts member-scoped module grant but evaluator ignores it (F-02).

**Recommendation:** A. Reject membership-scoped module grant requests explicitly. Retain member scope only for feature exceptions.

**Implementation status:** The follow-up migration adds a module-scope check constraint and explicit RPC rejection. It preflights incompatible existing rows and aborts with their grant IDs; it does not rewrite historical grants.

**Product owner approval:** Confirm that module availability is always tenant-wide and that a tenant may enable a module while feature access is restricted to specific memberships.

## D-05 — MFA and step-up for platform and high-impact actions

**Question:** What assurance level is required for Owner/Subowner sessions and sensitive platform actions?

**Options:**

- **A. Require MFA and step-up through Supabase Auth/Laravel for operator login and each high-impact action (recommended).** Advantages: stronger protection for cross-company authority and entitlement grants. Disadvantages: enrollment/recovery and support procedures are needed.
- **B. Require MFA at login only.** Advantages: simpler user experience. Disadvantages: long sessions and sensitive actions may proceed after assurance becomes stale.
- **C. No MFA requirement.** Advantages: least friction. Disadvantages: unacceptable exposure for an account that can control every tenant.

**Security impact:** Existing migrations do not check JWT AAL/MFA claims (P-03). RLS operator role alone does not establish the assurance of the current session.

**Data-model impact:** May require no core business table, but app policy, session assurance, audit event and possibly privileged-action evidence must be defined. Do not store raw MFA secrets in business tables.

**Recommendation:** A, with recovery and break-glass controls.

**Product owner approval:** Approve required AAL, step-up triggers, recovery options, operator lockout process and who can perform emergency access.

## D-06 — Person, employee, contractor and membership identity

**Question:** How should a human being relate to login access and one or more companies?

**Options:**

- **A. Keep membership as access; later add tenant-scoped Person/Worker with optional membership link (recommended).** Advantages: supports non-login workers, contractor users and employment history without overloading IAM. Disadvantages: introduces identity-resolution and duplicate-person workflows.
- **B. Treat each membership as the employee.** Advantages: small initial model. Disadvantages: cannot represent worker without login, multiple employment episodes, rehire or separate contact/employment history.
- **C. Create one global employee/person shared across all tenants.** Advantages: cross-tenant identity deduplication. Disadvantages: privacy leakage and complex consent/tenant ownership concerns.

**Security impact:** Personnel, medical and employment data require stricter roles, retention, audit and possibly field-level access. Cross-company person matching can leak that a person works for another tenant.

**Data-model impact:** HR should own person/worker, employment episode, contract, position and qualification. Auth membership remains a separate optional login link. Decide whether a person may relate to multiple tenants before finalizing key structure.

**Recommendation:** A, tenant-scoped by default. Design cross-tenant person identity only if customer requirements justify it.

**Product owner approval:** Decide non-login worker support, contractor worker support, multi-company worker relationships and whether HR is in the first ERP release.

## D-07 — Organization-unit hierarchy and scope inheritance

**Question:** Does access to an organizational unit include descendants?

**Options:**

- **A. Exact unit only; descendants require explicit scope (recommended initially and matches current SQL).** Advantages: predictable least privilege and simple authorization. Disadvantages: more scope assignments for large trees.
- **B. Inherit to descendant org units.** Advantages: convenient management for hierarchical companies. Disadvantages: hierarchy changes can widen access unexpectedly and require closure/recursive policy/index design.
- **C. Configurable per role/tenant.** Advantages: flexible. Disadvantages: harder to explain and test; creates policy variance.

**Security impact:** Inheritance changes the reachable row set and can silently widen a person's access when the org tree changes. It must be explicit in RLS and history, never frontend-only.

**Data-model impact:** Current org-unit access is exact. Recursive inheritance may require a closure path, hierarchy versioning or controlled recursive queries, plus an audit of descendants gained/lost.

**Recommendation:** A until a customer use case demonstrates a need; if B is chosen, make inheritance mode a tenant policy with audited changes and parity tests.

**Product owner approval:** Approve exact-vs-descendant semantics, including behavior when units move, merge or split.

## D-08 — Dynamic form schema and answer validation

**Question:** Which form constructs are supported, and where is the JSON schema contract validated?

**Options:**

- **A. Versioned form definition JSON with publish-time and submit-time schema validation (recommended).** Advantages: preserves flexible form builder and immutable form version; protects answer keys/types. Disadvantages: requires versioned validator and migration strategy when the builder evolves.
- **B. Store only fields used by reports as normalized rows; everything else as JSON.** Advantages: relational reporting where needed. Disadvantages: requires a clear, stable reportable-field list.
- **C. Fully normalize each form question/answer.** Advantages: strongest direct relational validation/query. Disadvantages: high schema complexity for conditional/repeat/bilingual builders and dynamic tenant fields.

**Security impact:** Malformed JSON can undermine required-field enforcement and reporting but does not itself grant tenant access. Form field-level sensitivity may require answer redaction and audit policy.

**Data-model impact:** Current title/definition/snapshot/answers are JSONB with only top-level type checks. An immutable version should carry schema version/hash; inspection should pin exact version; application validates answers against it. Frequently queried safety dimensions may be promoted to typed entities or indexable generated/relational facts.

**Recommendation:** A, with targeted relational projections for established reporting dimensions.

**Product owner approval:** Approve supported field types, conditions/repeat groups, locale policy, required-answer rules, scoring, form draft/publish/edit semantics, and audit treatment of form edits.

## D-09 — HSE case taxonomy: observation, incident, hazard and risk

**Question:** Which safety objects are distinct, and which workflows share records?

**Options:**

- **A. Keep inspection finding; add separately typed incident/near-miss and hazard/risk/control lifecycles (recommended).** Advantages: preserves source meaning and supports safety-specific fields, reporting and privacy. Disadvantages: more entities and cross-links.
- **B. Broaden finding into one generic case table with case_type and many nullable fields.** Advantages: one search surface. Disadvantages: sparse columns, conditional integrity, privacy and reporting risk.
- **C. Store all event data in form JSON or generic JSONB.** Advantages: fast schema changes. Disadvantages: cannot support dependable lifecycle, typed links or regulatory reporting.

**Security impact:** Incident injury/health details may need narrower visibility than ordinary findings. Queries and exports must enforce those restrictions.

**Data-model impact:** There are no incidents, hazards, assessments, controls or risk registers now. Current findings require an inspection and cannot correctly represent a standalone incident/near miss. HSE objects should all carry tenant/site and preserve source/owner/history.

**Recommendation:** A. Add typed entities only after safety taxonomy, severity, regulator reporting, cause analysis, control effectiveness and privacy rules are approved.

**Product owner approval:** Approve what counts as a finding vs observation vs hazard vs incident/near miss, required severity/risk matrix, link semantics and incident confidentiality requirements.

## D-10 — Inspection scheduling and review workflow

**Question:** Does HSE require recurrence and configurable approval chains in the first usable release?

**Options:**

- **A. Fixed three-stage reviewer chain plus schedule/occurrence entities only as required for launch (recommended if current customer process matches).** Advantages: preserves current implementation and keeps first workflow understandable. Disadvantages: may not fit clients with different review stages or frequency.
- **B. Tenant-configurable workflow definitions with versioned instances, steps, assignment and decision history.** Advantages: adaptable across companies/modules. Disadvantages: complex authorization, migration, SLA, version-change and failure behavior; too early without multiple stable consumers.
- **C. External workflow service.** Advantages: mature orchestration options. Disadvantages: integration, data residency, retry, audit and cross-service transaction complexity.

**Security impact:** Workflow transitions are authorization boundaries. Changing stages or delegated approvers must not grant broader record access. Approval history must be immutable and bind actor, stage version and tenant.

**Data-model impact:** Current workflow is hard-coded to reviewer_1/reviewer_2/final_reviewer. Inspections lack recurrence, due dates and schedule version. A schedule and occurrence are separate concepts from the completed inspection.

**Recommendation:** Decide fixed chain against launch customers. Add schedule/occurrence only when recurrence is a requirement. Do not build generic workflow engine until more than one domain validates the abstraction.

**Product owner approval:** Approve stage count/order, reviewer assignment, return/reopen rules, substitute/delegation, SLA/escalation, inspection recurrence, timezone and cancellation behavior.

## D-11 — Evidence storage, retention, version and signed-link policy

**Question:** Is Supabase Storage acceptable for HSE launch, and what retention/security behavior is required?

**Options:**

- **A. Private Supabase Storage, metadata in Postgres, short-lived authorized URLs (recommended for initial release if provider requirements fit).** Advantages: current RLS/policy alignment and fewer integration systems. Disadvantages: provider lock-in and signed URLs may remain usable until expiry after permission revocation.
- **B. S3-compatible object storage through a server authorization endpoint.** Advantages: portable lifecycle, customer-specific storage and scanning options. Disadvantages: separate signing/IAM and authorization implementation.
- **C. Proxy every download through Laravel.** Advantages: immediate authorization check and centralized redaction/audit. Disadvantages: bandwidth, latency and server cost.

**Security impact:** Object path is not authorization. Signed URLs are bearer capabilities. Rejected/pending files, malware scan and permission revocation require explicit handling.

**Data-model impact:** Current hse.evidence_files holds object metadata and one HSE polymorphic link; no file version, hash or scan state. Define whether replacing an upload creates a new immutable version or new evidence record. Avoid a shared document model until other modules need it.

**Recommendation:** A for initial HSE if customer residency, retention and scanning requirements allow; short TTL and no URL logging. Verify real Storage API behavior before production. Consider B/C for strict revocation or customer-controlled storage.

**Product owner approval:** Approve storage vendor/region, file limits/types, malware scanning, versioning, retention/legal hold, signed-link duration and delete/anonymize rules.

## D-12 — Audit history, event retention and data minimization

**Question:** What must be auditable for legal/compliance purposes, for how long, and with what redaction?

**Options:**

- **A. Append-only DB change ledger plus module-owned business histories and external log retention (recommended).** Advantages: separates row changes from workflow semantics and supports investigation. Disadvantages: duplicate storage and controlled retention/export operations.
- **B. Treat audit.events as complete business history.** Advantages: one table and simple search. Disadvantages: generic diffs do not encode workflow meaning or all external actions; current actor context may be missing.
- **C. Emit domain events only.** Advantages: replay and integrations. Disadvantages: requires event contracts, outbox consistency and projections; too broad for current stage.

**Security impact:** Audit values can contain personal or sensitive data; actor provenance, read/download events, failed access and exports may also matter. Append-only must include retention/legal hold and privileged access.

**Data-model impact:** Current audit is append-only with selected allowlisted diffs, but not Auth/Storage HTTP events, complete business events, or a retention/partition strategy. audit record_id is UUID and cannot directly identify non-UUID IDs without a separate representation.

**Recommendation:** A. Keep module histories for lifecycle and append-only audit for who changed selected data. Define redaction and retention by record category before incident/HR rollout.

**Product owner approval:** Approve record classes, write/read/export audit needs, retention periods, legal hold, personal data redaction and platform operator visibility.

## D-13 — Tenant domain ownership verification

**Question:** How does a company prove it may use a custom domain, and what happens when ownership changes?

**Options:**

- **A. DNS TXT challenge with one-time random proof and verified timestamp/actor (recommended for self-service).** Advantages: verifiable and automatable. Disadvantages: DNS propagation and renewal/support behavior.
- **B. Manual platform review and external verification.** Advantages: human support for edge cases. Disadvantages: slower, less scalable and needs evidence log.
- **C. Trust the company admin to mark verified.** Advantages: simplest. Disadvantages: enables domain-claim abuse and login-routing confusion.

**Security impact:** A domain used for routing or identity discovery must not be claimed without proof. Authentication must not infer tenant access solely from email domain.

**Data-model impact:** core.tenant_domains records domain/status/verified_at but not challenge lifecycle, proof method, expiration or revalidation.

**Recommendation:** A or B; never C. Keep domain association separate from membership authorization.

**Product owner approval:** Approve supported domain formats, proof method, renewal, transfer/dispute and whether email domain is used only for display, invitation suggestions or login routing.

## D-14 — Platform billing, pricing, taxes and payment provider

**Question:** What commercial market and accounting requirements apply to SENTRIQ’s own SaaS invoices?

**Options:**

- **A. Keep DB ledger as internal source, integrate one provider through verified idempotent webhooks after markets/prices are approved (recommended).** Advantages: preserves tenant entitlement ledger and stable pricing snapshots. Disadvantages: reconcile external provider state and plan changes.
- **B. Let payment provider be sole billing source.** Advantages: provider handles collection/subscriptions. Disadvantages: entitlement checks need robust sync and provider outages/retries can drift access.
- **C. Treat core invoices/payments as a full accounting ledger.** Advantages: apparent reuse. Disadvantages: current model lacks tax, credits, double-entry and reconciliation semantics; inappropriate for customer ERP finance.

**Security impact:** Browser callbacks must never grant access. Provider signatures, replay protection, amount/currency verification and webhook idempotency are mandatory.

**Data-model impact:** Core commercial tables record platform billing only. Existing plan seed is unpriced. P-04 in the security review is a lifecycle/product concern: a future-start subscription is inserted active and may reserve a live slot before entitlement starts.

**Recommendation:** A; retain provider boundary, approve pricing/currencies/tax invoice policy, and represent scheduled subscription lifecycle deliberately.

**Product owner approval:** Approve launch markets, payment provider, currencies, tax/VAT, invoice numbering, refunds/credits, dunning, trial and future subscription semantics.

## D-15 — Shared workflow, tasks, notifications and documents

**Question:** Which common services are required across more than one module, and when should they be built?

**Options:**

- **A. Keep current HSE workflow/evidence/actions module-owned; generalize only when a second domain shares stable requirements (recommended).** Advantages: avoids premature generic abstractions and keeps authorization near the domain. Disadvantages: later extraction may require a migration.
- **B. Build general workflow/task/document services before HSE completion.** Advantages: shared UX and event handling. Disadvantages: broad schema, tenancy and policy design before actual consumers are known.
- **C. Use external workflow/document products.** Advantages: mature product capability. Disadvantages: identity, data residency, authorization, retry and audit integrations.

**Security impact:** Shared engines must not become a permission bypass. Task notification is not task authorization; document access follows parent business record and tenant scope.

**Data-model impact:** Current task assignments are HSE security bindings, not work queue items; action updates are not general comments; evidence is HSE-specific. A future service should have explicit typed source links, tenant context, assignment/actor history and retry semantics.

**Recommendation:** A for initial release; revisit after real HSE and Operations workflows are specified.

**Product owner approval:** Approve which capabilities are launch requirements: generic tasks, email/in-app notifications, approval configuration, document library, activity feed or report builder.

## D-16 — Delegation and temporary access semantics

**Question:** Can a member delegate permissions or scope, and who approves/ends that access?

**Options:**

- **A. No delegation in first HSE release; use explicit role/scope grant and revoke by manager (recommended).** Advantages: simple effective-access calculation. Disadvantages: less coverage for absence/shift handover.
- **B. Time-bounded delegation with originating grant, delegator, delegate, approver, scope, reason and revocation.** Advantages: auditable and suitable for temporary coverage. Disadvantages: needs non-escalation rules, conflict resolution and lifecycle UI.
- **C. Copy grants into delegate’s direct permissions.** Advantages: easy implementation. Disadvantages: loses source authority, expiry and revocation cascade.

**Security impact:** Delegation cannot exceed delegator’s effective privilege or escape tenant/site/org scope. Revoking a source permission must revoke dependent delegates.

**Data-model impact:** Role assignment intervals exist, but direct grants/site access/task assignments do not all have consistent expiration or delegation provenance.

**Recommendation:** A until there is a confirmed workflow; if B is approved, model provenance and expiry explicitly rather than copying access.

**Product owner approval:** Approve delegate eligibility, approver, maximum duration, scope ceiling, automatic expiration, cascade revocation and audit visibility.

## D-17 — Future module order and Finance ownership

**Question:** Which customer workflows and industries should determine implementation of ERP modules, and does Finance mean operations billing or full customer books?

**Options:**

- **A. Sequence by validated customer workflows: HSE first, then People/Operations/Assets, then Procurement/Inventory, then Finance (recommended as an initial dependency order).** Advantages: reuses real shared foundations and avoids premature accounting scope. Disadvantages: sequence changes if customer demand differs.
- **B. Build Finance alongside the first HSE release.** Advantages: attractive “ERP” positioning. Disadvantages: accounting, tax, legal entity and reconciliation requirements are large and not evidenced.
- **C. Build a module shell for all domains before any workflow.** Advantages: breadth in navigation. Disadvantages: empty modules do not create operational value and encourage generic data models.

**Security impact:** Each module needs separate permission vocabulary, entitlements and tenant RLS. A module registry row is not sufficient enforcement or readiness.

**Data-model impact:** No HR, Operations, Assets, Procurement, Inventory or customer Finance tables exist. Existing invoices/payments exclusively serve SENTRIQ commercial entitlement flows.

**Recommendation:** A, but prioritize from customer discovery. Finance should be a separate accounting product scope with legal and jurisdiction decisions before migrations.

**Product owner approval:** Approve target customer vertical, first operational workflow after HSE, module roadmap, and whether Finance is a full ledger or external integration boundary.

## D-18 — Data retention, closure, archival and export

**Question:** What happens to tenant records when a user leaves, a company suspends/closes, a customer requests export or deletion, or a regulation requires retention?

**Options:**

- **A. Define retention per record class with reversible closure, legal hold, export and controlled anonymization (recommended).** Advantages: balances compliance, audit and privacy. Disadvantages: requires operational tooling and customer support process.
- **B. Preserve everything indefinitely.** Advantages: simplest operationally. Disadvantages: privacy, cost, backup and legal risk.
- **C. Cascade-delete a tenant and related records on closure.** Advantages: simple deletion behavior. Disadvantages: destroys safety/commercial audit and may conflict with legal retention.

**Security impact:** Closed/suspended tenants must lose interactive access while platform-authorized retention/export remains tightly controlled and audited.

**Data-model impact:** Existing status/revocation and RESTRICT FKs favor soft lifecycle. There is no archive, retention schedule, export job, deletion request, legal hold or backup expiry policy.

**Recommendation:** A. Retain business history according to approved class-specific rules; perform authorized anonymization where lawful.

**Product owner approval:** Approve periods and actions for identity, HSE incident/evidence, audit, billing, employment, uploaded files, backups and legal holds.

## Decision sequence

Resolve the security-critical choices D-01 through D-05 before customer user onboarding. Resolve HSE product semantics D-08 through D-11 before expanding HSE entities. Resolve future person and module decisions D-06, D-15, D-17 and D-18 before adding HR/Operations/Finance schema. These recommendations do not grant approval on behalf of the owner.
