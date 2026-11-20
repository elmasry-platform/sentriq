# SENTRIQ Domain Catalog

## Purpose and ownership rules

This catalog distinguishes platform-operated data from tenant-owned business data and module-owned transactional data. Supabase Auth users are external shared identities; a tenant membership associates an identity with a company. A company management level is not a business permission role. All tenant-owned records need a tenant boundary, and every cross-domain link must preserve that same tenant unless an explicitly approved platform relationship exists.

Module access remains company-level. Feature entitlements can be tenant-wide or membership-specific. A feature grant never bypasses the parent module. No future module should create its own identity, company, or permission system.

Recommended phase labels are relative sequence only, not delivery dates:

- Foundation: close trust/security gaps and define shared tenant/identity contracts.
- HSE completion: finish safety workflows after business lifecycle choices are approved.
- Shared services: introduce reusable capabilities only when multiple modules need the same stable service.
- Future ERP: add HR, Operations, Assets, Procurement, Inventory and Finance as separately scoped domains.

## Platform and commercial domains

### Platform operator authority

- **Purpose:** SENTRIQ-level company and entitlement administration.
- **Core entities:** iam.platform_operators; Supabase Auth auth.users is an external identity.
- **Relationships:** one Auth identity may be the platform Owner/Subowner but is explicitly prohibited from becoming a company membership; Owner lifecycle uses a narrow API RPC.
- **Boundary:** platform-wide authority, not tenant business data. Only the Owner creates/reactivates/deactivates Subowners. Subowners cannot manage the Subowner roster.
- **Dependencies:** verified Auth identity, MFA/step-up, audit attribution, service/API authorization.
- **Current status:** represented with owner/subowner role, active/deactivated state, creator and a unique active-owner rule. Owner bootstrap is a privileged installation step.
- **Phase:** Foundation. Confirm owner recovery, MFA/step-up, break-glass and audit policy before real users.

### Tenant/company and structure

- **Purpose:** establish one isolated customer company and its organizational/site access boundaries.
- **Core entities:** core.tenants, core.org_units, core.sites, core.tenant_domains.
- **Relationships:** tenant owns org units, sites and domains; org units can have a tenant-qualified parent; sites optionally reference a same-tenant org unit.
- **Boundary:** all company data uses tenant identity; domain claims are globally unique. A site is not a second tenant.
- **Dependencies:** IAM membership and RLS; future tenant configuration and lifecycle.
- **Current status:** tenant name/industry/status, hierarchical org unit, site code/name/city/status, domain status and verification timestamp. No full company settings, DNS proof, lifecycle runbook, data export, or closure retention flow.
- **Phase:** Foundation. Keep the org unit/site core stable before modules add their own locations.

### Product module and feature catalog

- **Purpose:** register product capabilities and evaluate licensing.
- **Core entities:** core.modules, core.features, core.plans, core.plan_entitlements.
- **Relationships:** feature belongs to one module; plan entitlement targets exactly one module or feature; module entitlements are tenant-scoped; feature grants may also target a membership.
- **Boundary:** module authorization is company-level. Membership-specific module grant must be rejected. Membership-level exceptions are features only, and still require the parent module.
- **Dependencies:** tenant lifecycle, commercial rules, effective authorization, audit.
- **Current status:** module/feature enabled state and commercial catalog exist; Operations has a module key but no domain implementation. Plan catalog is seeded as draft and unpriced. No module version/dependency or rollout metadata.
- **Phase:** Foundation. Approve module and feature lifecycle, then keep registry changes separate from business data migrations.

### Subscriptions and commercial exceptions

- **Purpose:** track SENTRIQ’s commercial access agreements.
- **Core entities:** core.subscriptions, core.subscription_items, core.entitlement_grants, legacy core.tenant_entitlements.
- **Relationships:** subscription belongs to tenant and plan; items refer to plan entitlements and freeze rate/currency/period; grants link one module or feature to tenant or feature membership, with grantor, reason, billing treatment and period.
- **Boundary:** tenant records cannot inspect platform pricing or commercial ledgers under ordinary roles. Grant decisions are platform operations. Bill-to tenant behavior is same-tenant under current constraints.
- **Dependencies:** owner-approved pricing, provider integration, usage, invoices, policy for complimentary/platform-paid access.
- **Current status:** normalized ledger, entitlement checks and legacy switch backfill exist. No payment provider, billing portal, tax/accounting integration or parent-company billing contract.
- **Phase:** Foundation for entitlement correctness; provider/accounting integration is a separate commercial decision.

### Usage, platform invoices and payments

- **Purpose:** meter SENTRIQ licensed usage and record internal SaaS billing.
- **Core entities:** core.usage_events, core.invoices, core.invoice_items, core.payments.
- **Relationships:** usage is tenant/member/feature scoped and optionally linked to grant; invoice items link to at most one usage event/grant/subscription item; payment belongs to invoice.
- **Boundary:** service-only billing operations and platform financial visibility. Usage idempotency key is globally unique after stabilization. Critical monetary amounts are integer minor units with currency snapshots.
- **Dependencies:** entitlement records, service actor identity, provider webhook/retry design, tax and jurisdiction policy.
- **Current status:** internal ledger and concurrency-safe paths are documented; external payment and invoice compliance are not implemented.
- **Phase:** Foundation hardening only when invoicing SENTRIQ customers; do not reuse as customer Finance.

### Tenant configuration and domains

- **Purpose:** store company-controlled operational preferences and safe routing/branding options.
- **Core entities needed:** approved typed tenant settings/configuration concepts; tenant domains with proof/verification operation. Names and grouping depend on product policy.
- **Relationships:** settings belong to tenant and possibly a module; sensitive secrets reference a secret manager, never raw credential JSON.
- **Boundary:** tenant cannot configure another tenant or override platform security. Domain verification must prove ownership outside a simple status update.
- **Dependencies:** authentication, UI host resolution, module lifecycle, audit.
- **Current status:** no general settings model; domain table tracks a status but not the proof.
- **Phase:** Foundation after settings/use cases and precedence have been listed.

## Identity, organization and authorization domains

### Shared identity and tenant membership

- **Purpose:** connect authenticated people to one or more companies and maintain per-company access state.
- **Core entities:** external auth.users; iam.memberships; iam.invitations; future people/worker profile is separate from membership.
- **Relationships:** Auth identity may join multiple tenant memberships; membership has management level, lifecycle and limited display contact fields. Invitation targets tenant/email and is accepted by a verified matching identity.
- **Boundary:** Auth proves identity, membership proves company association. Neither a browser-supplied tenant ID nor UI role selection is authority.
- **Dependencies:** Auth JWT verification, invitation email delivery, membership lifecycle RPC, security audit.
- **Current status:** DB supports multiple tenant memberships and verified-token acceptance RPC. F-01 confirms direct authenticated table policies still allow active member creation/activation around that acceptance path.
- **Phase:** Foundation security remediation. Later introduce person/employment entities for HR without turning membership into an employment record.

### Company management levels

- **Purpose:** allow tenant management by Company Superadmin and optionally delegate limited work to Company Admin; Employee is the basic access membership level.
- **Core entities:** iam.memberships.member_role and status.
- **Relationships:** management level gates manager functions; functional roles grant specific business actions separately.
- **Boundary:** tenant-only. It cannot confer platform Owner/Subowner privileges. Functional roles cannot grant management levels.
- **Dependencies:** membership activation security and effective permission logic.
- **Current status:** company_superadmin/company_admin/employee values, with one active Company Superadmin per tenant. Company Superadmin has HSE permission shortcut after HSE module entitlement. Company Admin does not inherit superadmin management authority.
- **Phase:** Foundation; approve exact Company Admin delegation surface and document superadmin operational policy.

### Functional RBAC and direct grants

- **Purpose:** express reusable role capabilities and individualized permissions for business functions.
- **Core entities:** iam.permission_catalog, iam.roles, iam.role_permissions, iam.membership_roles, iam.member_permissions.
- **Relationships:** role bundles permission/scope kinds; membership-role assignment binds role to tenant member and period; direct grant targets one member and scope.
- **Boundary:** functional roles may not represent platform or company management, billing, access management, scopes, or role administration.
- **Dependencies:** canonical permission names, PHP AccessResolver, RLS predicates, scope bindings, lifecycle history.
- **Current status:** normalized schema and protected global role seeds exist. Catalog is concentrated on HSE and company structure. Revocation is partly mutable current state.
- **Phase:** Foundation contract and parity; extend permissions along with specific module transactions.

### Site, organization and task scopes

- **Purpose:** narrow the data area an otherwise permitted membership can act on.
- **Core entities:** iam.site_access, iam.org_unit_access, iam.membership_role_sites, iam.membership_role_org_units, iam.task_assignments.
- **Relationships:** membership access rows establish site/org availability; role assignment scope binds a functional role; task row binds a member to an HSE record, with trigger-resolved tenant/site/org.
- **Boundary:** require functional permission plus site/org access. Task assignment cannot grant a missing permission or widen site/org scope. Org descendants do not implicitly inherit.
- **Dependencies:** accurate site/org ownership, task-specific target validation, module authorization.
- **Current status:** strong scope-intersection logic exists for HSE; generic task table does not. Some access rows use mutable active state rather than full temporal audit.
- **Phase:** Foundation invariant; later shared Tasks only after Operations/other modules identify common lifecycle semantics.

### Effective authorization and application API

- **Purpose:** produce consistent action-level allow/deny decisions across UI/API, background jobs and SQL.
- **Core entities:** current SQL helpers private.can_access_tenant/core/hse, has_hse_permission, has_module_entitlement and has_feature_entitlement; future PHP AccessResolver and trusted service identity contract.
- **Relationships:** verified Auth identity -> active tenant membership -> tenant module -> optional feature -> functional permission -> scope -> record lifecycle.
- **Boundary:** PostgreSQL RLS and constraints are the row boundary. Laravel provides route/action checks and usable error behavior. UI feature visibility is not enforcement.
- **Dependencies:** backend/API implementation, non-BYPASSRLS user path, DB grant/role design, allow/deny parity vectors.
- **Current status:** SQL enforcement exists for the database-only repo. No application server or current UI adapter is included.
- **Phase:** Foundation before wiring customer users.

### Delegation, temporary access, MFA and service identity

- **Purpose:** safely grant access for a bounded interval, record delegation, require step-up for critical roles, and attribute server actions.
- **Core entities needed:** current time-bound role/scope data partially covers access; additional delegation/approval, session assurance and job actor concepts require decisions.
- **Relationships:** delegator, delegate, approval, interval and target scope; Auth user actor separate from server service identity and initiating user.
- **Boundary:** an active service key must never become proof that a browser has permission. Higher privilege requires MFA/step-up.
- **Dependencies:** chosen identity provider and session policy, audit schema, background jobs.
- **Current status:** MFA/AAL is not checked, temporary scope is inconsistent, and future backend actor provenance is unverified.
- **Phase:** Foundation security policy, then schema only for approved delegation needs.

## HSE domain

### Forms and inspections

- **Purpose:** configure tenant-specific inspections, preserve published definition, capture results at a site and route review.
- **Core entities:** hse.form_templates, hse.form_versions, hse.inspections, hse.inspection_reviews.
- **Relationships:** template owns versions; inspection pins template+version, site and inspector; review belongs to inspection and revision.
- **Boundary:** tenant/site, HSE module, functional permission, reviewer/task scope; a form snapshot is not mutable after publication.
- **Dependencies:** field schema contract and validator, assignment service, dynamic workflow choice, evidence.
- **Current status:** usable relational skeleton, JSONB form and answers, fixed three stages. No scheduler, version-aware answer validator or generic workflow.
- **Phase:** HSE completion, after form lifecycle and review SLA decisions.

### Findings, incidents, risk and controls

- **Purpose:** capture unsafe observations and manage safety risk from discovery to verified control.
- **Core entities:** current hse.findings are inspection-originated; future incident/near-miss, hazard, risk assessment, risk/control entities depend on safety requirements.
- **Relationships:** finding -> corrective action is represented; incident/hazard -> investigation -> risk/control/action is absent.
- **Boundary:** tenant/site and HSE permissions. Safety records may carry sensitive injury/health data; field-level privacy and retention need an explicit contract.
- **Dependencies:** shared person/worker domain, assets/operations linkage, risk matrix, regulator and jurisdiction requirements.
- **Current status:** findings/actions are partial; incident, hazard/risk and control domains are absent.
- **Phase:** HSE completion; decide incident vs observation vs hazard semantics before migrations.

### Corrective actions and follow-up

- **Purpose:** assign correction work and verify closure.
- **Core entities:** hse.corrective_actions, hse.action_updates, hse.follow_ups.
- **Relationships:** action links to required finding and inspection; updates preserve status/comment; follow-up belongs to an action.
- **Boundary:** site/org/task and owner membership constraints, distinct action-manage/update-assigned/close-review permission.
- **Dependencies:** incident/hazard links, workflow and evidence history.
- **Current status:** a good first CAPA slice, but lacks preventive classification, causal analysis, effectiveness verification, configurable closure approval and risk link.
- **Phase:** HSE completion, extend only after agreed CAPA lifecycle.

### HSE documents and evidence

- **Purpose:** associate private evidence with HSE cases and store bytes outside PostgreSQL.
- **Core entities:** hse.evidence_files; external private Storage bucket/object.
- **Relationships:** one evidence metadata row links to one of inspection/finding/action/follow_up using a trigger-validated polymorphic reference.
- **Boundary:** object key tenant/site prefix must match metadata and RLS decision; short-lived signed links and revocation semantics require API-level verification.
- **Dependencies:** Storage API, retention, malware scan, file hashing/version, cleanup jobs.
- **Current status:** private bucket and metadata access policy exist; only DB object RLS was probed in prior review, not HTTP signed/upload/download behavior.
- **Phase:** HSE completion for existing evidence. Shared document service only if other modules need cross-module document semantics.

## Shared enterprise service domains

### Workflow and approvals

- **Purpose:** represent approvals that share stable stage, actor, outcome, delegation, SLA and history requirements.
- **Core entities:** current HSE inspection/review records. A future shared workflow should separate workflow definition/version, instance, step, assignment and decision only after cross-module requirements stabilize.
- **Relationships:** business record owns or references a workflow instance; approval decisions refer to one step, actor, time and immutable workflow revision.
- **Boundary:** module policy still determines which permissions and tenant scopes may perform a step; a workflow engine must not grant data access.
- **Dependencies:** HSE workflow and second consuming module.
- **Current status:** HSE-specific trigger implementation only.
- **Phase:** Shared services, not a launch prerequisite to HSE.

### Notification, tasks, comments and timeline

- **Purpose:** deliver actionable work and capture communication and history.
- **Core entities needed:** notification event/delivery attempt/preferences; tasks/work queue; comments/activity references.
- **Relationships:** event has tenant, recipient, source record, channel and attempts; task references owning domain and assignment; comments need immutable actor/time and access through parent record.
- **Boundary:** access must resolve through source record, recipient, tenant and site scope. Notification payloads should avoid sensitive case data and tokens.
- **Dependencies:** user directory, email/push provider, background jobs/outbox, preferences.
- **Current status:** only HSE assignment table and action updates/review reasons; no delivery or general task service.
- **Phase:** Shared services when HSE release workflows require reliable delivery; do not conflate task assignment with grants.

### Audit, reporting, integrations and jobs

- **Purpose:** support compliance, analytics, provider connectivity and reliable asynchronous processing.
- **Core entities:** current audit.events and billing idempotency controls; future outbox/report definitions/exports/external-ID mappings/webhook deliveries/job runs as requirements emerge.
- **Relationships:** event sources are tenant business records; reports materialize approved filtered snapshots; integrations track external identity and sync position; jobs hold idempotency and attempts.
- **Boundary:** audit is append-only, scoped, minimal and actor-attributed; exports and integration tokens require dedicated authorization and secret management.
- **Dependencies:** business lifecycle, retention, privacy, monitoring and support model.
- **Current status:** application audit and selected idempotent billing paths exist. No generic report, outbox, integration, delivery retry or job runtime.
- **Phase:** Foundation security observability first; shared service models later based on actual module consumers.

## Future ERP domains

| Domain | Purpose and principal entities | Boundary and dependencies | Current status | Recommended phase |
|---|---|---|---|---|
| HR and people | Person/worker, employee profile, employment episode, department/position, contract, attendance, leave, qualification, external worker. | Tenant-owned employment; link to shared Auth/membership when the person has a login. A non-login worker must still be representable. Needs privacy, legal retention, manager hierarchy and HR permissions. | Not implemented; membership is not employee record. | Future ERP foundation after requirements for workforce identity and privacy. |
| Operations | Work order, request, checklist, shift/team, work center, service/production operation and completion history. | Tenant/site; may reference employee/worker, asset, inventory, HSE permit/risk, but should own operational lifecycle. Needs domain vocabulary by target industry. | Module registry only; no operational tables. | Future ERP after selecting initial workflows/customer vertical. |
| Assets | Asset/category, serial/identifier, site/location, custody, state history, maintenance plan/work history, inspections. | Tenant-owned asset; location/assignment history; links to Operations and HSE by typed references. Requires asset identity, depreciation boundary and maintenance responsibility. | Not implemented. | Future ERP after Operations/HSE asset requirements. |
| Procurement | Supplier, requisition, quotation, purchase order, contract, approval, receipt and supplier invoice reference. | Tenant business; purchasing authority, supplier access, audit trail and approval lifecycle. Depends on item/catalog, budget/cost-center choice, finance integration. | Not implemented. | Future ERP after shared supplier/catalog and approval contracts. |
| Inventory | Item/SKU, unit, warehouse/bin, balance projection, stock movement, reservations, transfers, count and adjustment. | Tenant-owned ledger; each movement records source, destination, item, quantity, actor and time. Avoid treating a mutable balance as sole truth. Depends on item and procurement/operations flows. | Not implemented. | Future ERP after item/location and stock accounting decisions. |
| Finance | Chart of accounts, period, journal/line, AP/AR, tax, cost center, bank reconciliation and close. | Tenant-specific financial books and currency/tax policy, segregated from SENTRIQ platform billing. Depends on legal entity, fiscal calendar, tax jurisdiction, currency, posting rules and audit controls. | Not implemented; core invoices/payments are platform billing only. | Future ERP last, after jurisdiction/product scope and accounting ownership are selected. |

## Cross-domain dependency view

~~~mermaid
flowchart LR
  AUTH[Supabase Auth identity] --> IAM[Tenant membership and IAM]
  TEN[Tenant and org/site foundation] --> IAM
  IAM --> HSE[HSE records and policies]
  CORE[Module and feature entitlement] --> HSE
  IAM --> PEOPLE[Future people and employment]
  TEN --> PEOPLE
  PEOPLE --> OPS[Future operations]
  TEN --> OPS
  ASSET[Future asset register] --> OPS
  PEOPLE --> HSE
  ASSET --> HSE
  OPS --> PROC[Future procurement]
  ITEM[Future item catalog] --> PROC
  PROC --> INV[Future inventory]
  OPS --> INV
  INV --> FIN[Future customer finance]
  PROC --> FIN
  OPS --> FIN
  AUDIT[Shared audit and actor provenance] --- IAM
  AUDIT --- HSE
  AUDIT --- OPS
  DOC[Shared documents only if required] --- HSE
  DOC --- OPS
~~~

This is a conceptual dependency map. It does not assert these future domains exist in the repository or require immediate implementation.


## Shared platform and authorization ERD — current foundation

These current-state diagrams show the shared core/commercial and IAM entities used by HSE and future modules. Supabase Auth is an external dependency, not an application-owned table.

### Platform, tenant and commercial model

~~~mermaid
erDiagram
  AUTH_USERS {
    uuid id PK
  }
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
  }
  PAYMENTS {
    uuid id PK
    uuid tenant_id FK
    uuid invoice_id FK
  }
  MEMBERSHIPS {
    uuid id PK
    uuid tenant_id FK
    uuid user_id FK
  }

  TENANTS ||--o{ ORG_UNITS : owns
  ORG_UNITS o|--o{ ORG_UNITS : parent
  TENANTS ||--o{ SITES : owns
  ORG_UNITS o|--o{ SITES : contains
  TENANTS ||--o{ TENANT_DOMAINS : claims
  MODULES ||--o{ TENANT_ENTITLEMENTS : legacy_switch
  MODULES ||--o{ FEATURES : contains
  PLANS ||--o{ PLAN_ENTITLEMENTS : defines
  MODULES o|--o{ PLAN_ENTITLEMENTS : includes
  FEATURES o|--o{ PLAN_ENTITLEMENTS : includes
  TENANTS ||--o{ SUBSCRIPTIONS : subscribes
  PLANS ||--o{ SUBSCRIPTIONS : selected
  SUBSCRIPTIONS ||--o{ SUBSCRIPTION_ITEMS : contains
  PLAN_ENTITLEMENTS ||--o{ SUBSCRIPTION_ITEMS : prices
  TENANTS ||--o{ ENTITLEMENT_GRANTS : grants
  TENANTS ||--o{ MEMBERSHIPS : contains
  MEMBERSHIPS o|--o{ ENTITLEMENT_GRANTS : feature_exception
  TENANTS ||--o{ USAGE_EVENTS : meters
  FEATURES ||--o{ USAGE_EVENTS : measures
  TENANTS ||--o{ INVOICES : billed
  INVOICES ||--o{ INVOICE_ITEMS : contains
  INVOICES ||--o{ PAYMENTS : paid_by
  AUTH_USERS ||--o{ MEMBERSHIPS : authenticates
~~~

### IAM, roles and scope model

~~~mermaid
erDiagram
  AUTH_USERS {
    uuid id PK
  }
  TENANTS {
    uuid id PK
  }
  PLATFORM_OPERATORS {
    uuid user_id PK FK
    text operator_role
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
    uuid site_id FK
    uuid org_unit_id FK
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
  SITES {
    uuid id PK
    uuid tenant_id FK
  }
  ORG_UNITS {
    uuid id PK
    uuid tenant_id FK
  }

  AUTH_USERS ||--o| PLATFORM_OPERATORS : platform_actor
  AUTH_USERS ||--o{ MEMBERSHIPS : identity
  TENANTS ||--o{ MEMBERSHIPS : membership
  TENANTS ||--o{ INVITATIONS : invites
  TENANTS ||--o{ ROLES : defines
  ROLES ||--o{ ROLE_PERMISSIONS : bundles
  PERMISSION_CATALOG ||--o{ ROLE_PERMISSIONS : defines
  MEMBERSHIPS ||--o{ MEMBERSHIP_ROLES : receives
  ROLES ||--o{ MEMBERSHIP_ROLES : assigned
  MEMBERSHIP_ROLES ||--o{ MEMBERSHIP_ROLE_SITES : limited_to
  MEMBERSHIP_ROLE_SITES }o--|| SITES : site
  MEMBERSHIP_ROLES ||--o{ MEMBERSHIP_ROLE_ORG_UNITS : limited_to
  MEMBERSHIP_ROLE_ORG_UNITS }o--|| ORG_UNITS : unit
  MEMBERSHIPS ||--o{ MEMBER_PERMISSIONS : direct_grant
  MEMBERSHIPS ||--o{ SITE_ACCESS : site_access
  SITE_ACCESS }o--|| SITES : allows
  MEMBERSHIPS ||--o{ ORG_UNIT_ACCESS : org_access
  ORG_UNIT_ACCESS }o--|| ORG_UNITS : allows
  MEMBERSHIPS ||--o{ TASK_ASSIGNMENTS : assigned
~~~

Role permission and task target links are deliberately simplified in the diagram. The implementation uses a permission catalog FK and trigger-validated HSE polymorphic target kinds; a task binding narrows access but never grants functional permission.
