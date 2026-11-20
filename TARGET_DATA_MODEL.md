# SENTRIQ Target Data Model

## Model intent

This is a conceptual target for incremental evolution, not executable SQL and not a claim that the entities exist. It retains the established PostgreSQL/Supabase boundary and avoids redesigning current tables wholesale.

The platform foundation is shared. Each tenant-owned entity carries one tenant boundary, and cross-entity relationships preserve tenant identity through composite references or equivalent database invariants. Auth identity remains external to tenant business data. Platform authority stays separate from Company Superadmin/Admin/Employee management level and from functional permission roles.

Commercial access contract:

- Module entitlement belongs to a tenant and enables that business module for the company.
- Feature entitlement belongs to a tenant, with a specifically approved membership-level exception when needed.
- A feature never bypasses its parent module.
- A membership-level module grant is invalid and must be rejected.
- Business authorization is the intersection of active verified identity, tenant membership, tenant lifecycle, company module, feature when required, functional permission, data scope, and workflow/lifecycle rule.

## Entity ownership and boundaries

| Ownership | Conceptual entities | Boundary and rationale |
|---|---|---|
| Platform identity | Auth identity, platform operator, service identity, authentication/session assurance | Identity provider owns credentials. Platform operator is not a tenant member. Service principal is distinguishable from the initiating human actor. Require step-up for platform operators and sensitive platform actions. |
| Platform product catalog | Module, feature, plan version, plan entitlement, permission catalog, global protected functional role | Platform controls product definitions. Tenant users cannot edit pricing or global permission definitions. Module changes need version/dependency/lifecycle governance before the module count grows. |
| Tenant administration | Tenant, tenant domain claim/proof, organization unit, site, typed tenant settings | Each tenant controls its company structure/settings; platform verifies domain proof and enforces uniqueness. Settings should be typed/versioned and module-scoped only where useful, not an unvalidated JSON catchall. |
| Tenant access and commercial contract | Membership, invitation, tenant subscription, subscription item snapshot, entitlement grant, usage, platform invoice/payment | Membership is access. Employment/person records are separate. Tenant/subscription/grant scoping supports commercial audit; membership-scoped exceptions apply only to features. |
| Tenant IAM | Management level, tenant functional role, role permission, membership-role assignment, direct grant, site/org scope, task binding, delegation/approval | Functional permission never grants management power. Scope does not create permission. Temporary/delegated access carries approver, reason, validity and revocation history when approved. |
| Shared enterprise service | Workflow definition/version/instance/step/decision; task/work item; notification/delivery; activity/comment; document metadata/version; integration mapping; webhook delivery; job/outbox; report definition/export | Introduce each shared service only after multiple module consumers establish a stable lifecycle. All rows remain tenant-scoped unless truly platform-owned. Parent-record authorization is authoritative. |
| HSE module | Form, published version, schedule/occurrence, inspection/review, observation/finding, incident/investigation, hazard, risk assessment, control, corrective action, verification, permit, toolbox session, training/competency, audit obligation, drill, contractor and evidence link | HSE owns safety vocabulary and lifecycle. Typed safety records should be relational; flexible form content remains versioned JSON where schema variability is real. |
| Future HR/People | Person/worker, employment episode, position, contract, attendance/leave, qualification, contractor worker profile | Tenant business identity is distinct from Supabase login. A non-login worker must be representable. The relationship between one person and multiple tenants is a product/privacy decision. |
| Future Operations/Assets | Work request/order, shift, work center, operational checklist; asset/category/location/custody/maintenance history | Operations owns execution. Asset location/assignment/history are separate from current site. HSE may reference an asset through an explicit same-tenant relationship. |
| Future Procurement/Inventory | Supplier, requisition, purchase order/contract, receipt; item/UOM, warehouse/bin, stock movement/reservation/transfer/count | Procurement and inventory have distinct approval and immutable movement requirements. Model movements as facts; balances can be projections. |
| Future Finance | Customer legal entity/fiscal period, account, journal/line, AP/AR, tax, cost center, reconciliation | Customer books are separate from SENTRIQ platform billing and require approved jurisdiction, accounting and control policies. |

## Shared platform and authorization target ERD

~~~mermaid
erDiagram
  AUTH_IDENTITY ||--o{ MEMBERSHIP : proves
  AUTH_IDENTITY ||--o| PLATFORM_OPERATOR : platform_access
  AUTH_IDENTITY ||--o{ AUDIT_ACTOR : attributed_as
  TENANT ||--o{ MEMBERSHIP : contains
  TENANT ||--o{ ORG_UNIT : organizes
  ORG_UNIT o|--o{ ORG_UNIT : parent
  TENANT ||--o{ SITE : operates
  ORG_UNIT o|--o{ SITE : groups
  TENANT ||--o{ TENANT_DOMAIN_CLAIM : verifies
  TENANT ||--o{ TENANT_SETTING_VERSION : configures
  TENANT ||--o{ INVITATION : issues
  AUTH_IDENTITY o|--o{ INVITATION : redeems
  TENANT ||--o{ SUBSCRIPTION : contracts
  SUBSCRIPTION ||--o{ SUBSCRIPTION_ITEM : snapshots
  PLAN_VERSION ||--o{ SUBSCRIPTION : selected
  PLAN_VERSION ||--o{ PLAN_ENTITLEMENT : defines
  MODULE ||--o{ FEATURE : contains
  MODULE ||--o{ PLAN_ENTITLEMENT : prices
  FEATURE ||--o{ PLAN_ENTITLEMENT : prices
  TENANT ||--o{ ENTITLEMENT_GRANT : receives
  MEMBERSHIP o|--o{ ENTITLEMENT_GRANT : feature_exception
  TENANT ||--o{ USAGE_EVENT : meters
  TENANT ||--o{ FUNCTIONAL_ROLE : defines
  FUNCTIONAL_ROLE ||--o{ ROLE_PERMISSION : bundles
  PERMISSION ||--o{ ROLE_PERMISSION : catalog
  MEMBERSHIP ||--o{ MEMBERSHIP_ROLE : assigned
  FUNCTIONAL_ROLE ||--o{ MEMBERSHIP_ROLE : assigned_as
  MEMBERSHIP_ROLE ||--o{ ROLE_SCOPE : narrowed_by
  MEMBERSHIP ||--o{ DIRECT_PERMISSION_GRANT : exception
  MEMBERSHIP ||--o{ MEMBERSHIP_SCOPE : narrowed_by
  MEMBERSHIP ||--o{ TASK_BINDING : assigned
  MEMBERSHIP ||--o{ ACCESS_DELEGATION : delegates
  WORKFLOW_INSTANCE ||--o{ APPROVAL_STEP : sequences
  APPROVAL_STEP ||--o{ APPROVAL_DECISION : decided
  TENANT ||--o{ WORK_ITEM : queues
  TENANT ||--o{ NOTIFICATION_DELIVERY : delivers
  TENANT ||--o{ DOCUMENT_VERSION : stores
  TENANT ||--o{ BUSINESS_AUDIT_EVENT : records

  AUTH_IDENTITY {
    uuid id
    text provider
  }
  TENANT {
    uuid id
    text lifecycle
  }
  MEMBERSHIP {
    uuid id
    uuid tenant_id
    uuid identity_id
    text management_level
    text status
  }
  MODULE {
    text key
    boolean enabled
  }
  FEATURE {
    text key
    text module_key
  }
  FUNCTIONAL_ROLE {
    uuid id
    uuid tenant_id
    text role_key
  }
  PERMISSION {
    text key
    text module_key
  }
  MEMBERSHIP_ROLE {
    uuid id
    uuid membership_id
    timestamptz valid_from
    timestamptz valid_to
  }
  WORKFLOW_INSTANCE {
    uuid id
    uuid tenant_id
    text owner_domain
    uuid owner_record_id
  }
  BUSINESS_AUDIT_EVENT {
    bigint id
    uuid tenant_id
    uuid actor_identity_id
  }
  INVITATION {
    uuid id
    uuid tenant_id
    text token_hash
    timestamptz expires_at
    timestamptz accepted_at
  }
~~~

Conceptual edges express ownership and access. The final physical schema may choose typed relation tables or approved event references where a normal FK is not possible. Do not weaken tenant ownership to make a generic engine easier.

## HSE target ERD

The diagram shows an incremental target, not the current schema. Current entities appear in bold conceptually by name in the change notes below; Mermaid ER syntax does not convey implementation status.

~~~mermaid
erDiagram
  TENANT ||--o{ FORM_TEMPLATE : owns
  FORM_TEMPLATE ||--o{ FORM_VERSION : publishes
  FORM_VERSION ||--o{ INSPECTION : instantiated_as
  INSPECTION ||--o{ INSPECTION_REVIEW : reviewed
  INSPECTION ||--o{ SAFETY_FINDING : identifies
  TENANT ||--o{ INSPECTION_SCHEDULE : configures
  INSPECTION_SCHEDULE ||--o{ INSPECTION_OCCURRENCE : plans
  INSPECTION_OCCURRENCE o|--o| INSPECTION : executes
  TENANT ||--o{ INCIDENT : owns
  INCIDENT ||--o{ INCIDENT_INVOLVED_PERSON : records
  INCIDENT ||--o{ INVESTIGATION : investigates
  TENANT ||--o{ HAZARD : registers
  HAZARD ||--o{ RISK_ASSESSMENT : assessed_by
  RISK_ASSESSMENT ||--o{ RISK_CONTROL_LINK : selects
  CONTROL_MEASURE ||--o{ RISK_CONTROL_LINK : mitigates
  INCIDENT ||--o{ INCIDENT_HAZARD_LINK : identifies
  HAZARD ||--o{ INCIDENT_HAZARD_LINK : referenced_by
  SAFETY_FINDING o|--o{ CORRECTIVE_ACTION : addressed_by
  INCIDENT o|--o{ CORRECTIVE_ACTION : addressed_by
  HAZARD o|--o{ CORRECTIVE_ACTION : addressed_by
  CORRECTIVE_ACTION ||--o{ ACTION_HISTORY : changes
  CORRECTIVE_ACTION ||--o{ ACTION_VERIFICATION : verifies
  TENANT ||--o{ WORK_PERMIT : issues
  WORK_PERMIT ||--o{ PERMIT_PARTICIPANT : authorizes
  TENANT ||--o{ TOOLBOX_SESSION : schedules
  TOOLBOX_SESSION ||--o{ ATTENDANCE_ACKNOWLEDGEMENT : records
  TENANT ||--o{ WORKER_COMPETENCY : tracks
  PERSON ||--o{ WORKER_COMPETENCY : holds
  TENANT ||--o{ COMPLIANCE_OBLIGATION : tracks
  COMPLIANCE_OBLIGATION ||--o{ HSE_AUDIT_INSTANCE : audited_by
  TENANT ||--o{ EMERGENCY_DRILL : exercises
  EMERGENCY_DRILL ||--o{ DRILL_PARTICIPANT : records
  TENANT ||--o{ EVIDENCE_OBJECT : owns
  EVIDENCE_OBJECT ||--o{ EVIDENCE_LINK : attached
  SAFETY_FINDING ||--o{ EVIDENCE_LINK : evidence
  INCIDENT ||--o{ EVIDENCE_LINK : evidence
  WORK_PERMIT ||--o{ EVIDENCE_LINK : evidence

  INCIDENT {
    uuid id
    uuid tenant_id
    uuid site_id
    timestamptz occurred_at
    text incident_type
    text severity
    text lifecycle_status
  }
  HAZARD {
    uuid id
    uuid tenant_id
    uuid site_id
    text hazard_type
    text lifecycle_status
  }
  RISK_ASSESSMENT {
    uuid id
    uuid tenant_id
    uuid hazard_id
    text method_version
    text residual_rating
  }
  CONTROL_MEASURE {
    uuid id
    uuid tenant_id
    text control_hierarchy
    text effectiveness_status
  }
  CORRECTIVE_ACTION {
    uuid id
    uuid tenant_id
    uuid site_id
    uuid owner_person_id
    text lifecycle_status
  }
  WORK_PERMIT {
    uuid id
    uuid tenant_id
    uuid site_id
    timestamptz valid_from
    timestamptz valid_to
    text lifecycle_status
  }
~~~

### HSE modeling notes

- Keep form field definition, localization, conditional layout and variable answer values in validated JSON tied to an immutable form version. The application validator must validate answers against the exact pinned version. Promote fields used as cross-form reporting dimensions or compliance controls into typed relations/columns where scale and query needs justify it.
- Keep business objects typed. Incident, hazard, risk assessment, control measure, permit, training credential and compliance obligation have different owners, privacy, lifecycle and audit requirements; a single JSON case table would hide relationships and make reporting/security brittle.
- Preserve finding as inspection-originated if that is the product meaning. Model stand-alone observations separately or explicitly allow a typed source relationship only after owner decision; do not silently relax its required inspection FK.
- A risk assessment should retain method/matrix version and separately record inherent and residual risk with factor definitions. Controls should be assignable to a risk and have effectiveness checks/history.
- Corrective actions should have typed source links (finding, incident, hazard, audit nonconformance, permit/drill) or explicit association rows with same-tenant safeguards. Keep action history and closure verification immutable.
- Inspection recurrence should distinguish a schedule/rule from each planned occurrence and completed inspection. Store timezone and local recurrence semantics. Do not use a cron-like text string as the sole auditable schedule.
- Evidence bytes remain in private object storage. Metadata should include content hash, scan/confirmation lifecycle and access classification as policy requires. A document version is different from a generic “linked record” pointer; preserve parent-record RLS and revocation semantics.
- HSE incident/injury data may be sensitive personal information. Define role separation, retention, exports and field-level disclosure before onboarding real incident records.

## Future ERP conceptual model

~~~mermaid
erDiagram
  TENANT ||--o{ PERSON : employs_or_engages
  PERSON ||--o{ EMPLOYMENT_EPISODE : employment_history
  MEMBERSHIP o|--o| PERSON : login_link
  ORG_UNIT ||--o{ POSITION : organizes
  PERSON ||--o{ POSITION_ASSIGNMENT : holds
  POSITION ||--o{ POSITION_ASSIGNMENT : assigned
  TENANT ||--o{ ASSET : owns
  ASSET_CATEGORY ||--o{ ASSET : classifies
  SITE ||--o{ ASSET_LOCATION_HISTORY : locates
  ASSET ||--o{ ASSET_LOCATION_HISTORY : history
  ASSET ||--o{ MAINTENANCE_ORDER : maintained_by
  TENANT ||--o{ WORK_ORDER : operates
  WORK_ORDER ||--o{ WORK_ORDER_ASSET_LINK : uses
  ASSET ||--o{ WORK_ORDER_ASSET_LINK : maintained_by
  PERSON ||--o{ WORK_ORDER_ASSIGNMENT : performs
  WORK_ORDER ||--o{ WORK_ORDER_ASSIGNMENT : assigned
  TENANT ||--o{ SUPPLIER : sources
  SUPPLIER ||--o{ PURCHASE_ORDER : receives
  PURCHASE_ORDER ||--o{ GOODS_RECEIPT : received
  TENANT ||--o{ ITEM : catalogs
  ITEM ||--o{ STOCK_MOVEMENT : moves
  WAREHOUSE ||--o{ STOCK_MOVEMENT : location
  PURCHASE_ORDER ||--o{ STOCK_MOVEMENT : received_as
  TENANT ||--o{ FINANCIAL_PERIOD : closes
  FINANCIAL_PERIOD ||--o{ JOURNAL_ENTRY : contains
  JOURNAL_ENTRY ||--|{ JOURNAL_LINE : balances
  ACCOUNT ||--o{ JOURNAL_LINE : posts
  COST_CENTER o|--o{ JOURNAL_LINE : allocates

  TENANT {
    uuid id
  }
  PERSON {
    uuid id
    uuid tenant_id
    text person_type
  }
  EMPLOYMENT_EPISODE {
    uuid id
    uuid person_id
    date valid_from
    date valid_to
  }
  ASSET {
    uuid id
    uuid tenant_id
    text asset_tag
  }
  WORK_ORDER {
    uuid id
    uuid tenant_id
    text lifecycle_status
  }
  ITEM {
    uuid id
    uuid tenant_id
    text sku
  }
  STOCK_MOVEMENT {
    uuid id
    uuid tenant_id
    numeric quantity
  }
  JOURNAL_ENTRY {
    uuid id
    uuid tenant_id
    uuid financial_period_id
    text status
  }
~~~

The entity sketches are dependency placeholders only. They do not decide HR/person sharing across tenants, asset depreciation, stock valuation, finance posting rules or industry-specific Operations workflows.

## Cross-domain relationship rules

1. Every tenant-owned table must have tenant ownership, row security, and policy tests for same-tenant allow and cross-tenant deny.
2. Cross-domain references should be explicit and constrained. If polymorphic references are required, keep their type allowlist narrow and implement a validator for each target with tenant/site match checks.
3. Membership is an authorization relationship. Person, employee, contractor and employment history are business entities. A worker without login must be representable.
4. Shared references such as person across customer companies require explicit privacy and identity resolution rules; do not assume one human record can be shared tenant-wide.
5. The module registry is not a substitute for domain ownership. Each module owns its transactional lifecycle and permission vocabulary while consuming shared tenant/identity/entitlement/audit services.
6. Audit events describe who changed what; domain history describes business lifecycle. Preserve both where required. Do not rely on generic audit JSON to reconstruct an approved workflow.
7. Authorization is enforced in Laravel and PostgreSQL. Service-role, migrations and background jobs use separate service identities, validated tenant/actor inputs and narrowly granted DB capabilities.

## Transition from current schema

- Retain core.tenants, org_units, sites, Auth-backed memberships, current functional-role tables, commercial ledgers, HSE forms/inspections/actions and audit records as the foundation.
- Database follow-up `codex/foundation-security-remediation` closes the membership activation bypass and settles F-02 module scope. Before application onboarding, bind service-role actor UUIDs to verified Auth identity in Laravel and confirm hosted migration-owner/data preflight obligations.
- Add only the approved extension entities: likely typed company settings/domain proof, but do not add generic workflow/tasks/documents until requirements justify them.
- Keep form title/definition/version snapshots and inspection answers in JSONB while adding schema validation at publish and submit boundaries.
- Add first-class HSE incident, hazard, risk/control and inspection schedule lifecycle after business decisions. Preserve old finding/action records and map forward with additive migrations; do not destructively reinterpret them.
- Add people/workforce records after deciding whether non-login workers and one-person/multi-tenant relationships must be supported.
- Introduce Operations, Assets, Procurement, Inventory and Finance in dependency order with independent module entitlement and tenant RLS.
