-- Forward-only SENTRIQ commercial entitlements, normalized RBAC, scope, audit,
-- invitation and workflow hardening. The initial migration remains unchanged.
begin;

-- Commercial catalog. Prices are deliberately absent until approved by the owner.
create table core.features (
  feature_key text primary key,
  module_key text not null references core.modules(module_key) on delete restrict,
  label text not null,
  description text,
  enabled boolean not null default true,
  usage_unit text,
  unique (feature_key,module_key)
);
insert into core.features(feature_key,module_key,label,description,usage_unit) values
 ('hse.copilot','hse','HSE Copilot','AI-assisted HSE capability, licensed separately from HSE','request');

create table core.plans (
  id uuid primary key default gen_random_uuid(), plan_key text not null,
  version integer not null check (version>0), name text not null,
  status text not null default 'draft' check (status in ('draft','active','retired')),
  currency char(3), price_minor bigint check (price_minor is null or price_minor>=0),
  created_at timestamptz not null default now(), unique(plan_key,version),
  check (status='draft' or (currency is not null and price_minor is not null))
);
create table core.plan_entitlements (
  id uuid primary key default gen_random_uuid(), plan_id uuid not null references core.plans(id) on delete restrict,
  module_key text references core.modules(module_key) on delete restrict,
  feature_key text references core.features(feature_key) on delete restrict,
  quota numeric(20,6) check (quota is null or quota>=0), usage_rate_minor bigint check(usage_rate_minor is null or usage_rate_minor>=0),
  usage_currency char(3),
  unique(plan_id,module_key), unique(plan_id,feature_key),
  check ((module_key is not null)::integer+(feature_key is not null)::integer=1)
);
insert into core.plans(plan_key,version,name,status) values('hse_base',1,'HSE base plan template — unpriced','draft');
insert into core.plan_entitlements(plan_id,module_key) select id,'hse' from core.plans where plan_key='hse_base' and version=1;
create table core.subscriptions (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  plan_id uuid not null references core.plans(id) on delete restrict,
  status text not null check (status in ('draft','trialing','active','past_due','suspended','canceled','expired')),
  starts_at timestamptz not null, current_period_start timestamptz not null, current_period_end timestamptz not null,
  cancel_at_period_end boolean not null default false, canceled_at timestamptz,
  created_by uuid not null references auth.users(id) on delete restrict, created_at timestamptz not null default now(),
  unique(tenant_id,id), check (current_period_start<current_period_end),
  check ((status='canceled')=(canceled_at is not null))
);
create unique index one_live_subscription_per_tenant on core.subscriptions(tenant_id)
  where status in ('trialing','active','past_due','suspended');
create table core.subscription_items (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, subscription_id uuid not null,
  plan_entitlement_id uuid not null references core.plan_entitlements(id) on delete restrict,
  quantity numeric(20,6) not null default 1 check (quantity>0),
  unit_price_minor bigint not null check (unit_price_minor>=0), currency char(3) not null,
  starts_at timestamptz not null, ends_at timestamptz,
  foreign key(tenant_id,subscription_id) references core.subscriptions(tenant_id,id) on delete restrict,
  check(ends_at is null or starts_at<ends_at), unique(subscription_id,plan_entitlement_id,starts_at), unique(tenant_id,id)
);
create table core.entitlement_grants (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  module_key text references core.modules(module_key) on delete restrict,
  feature_key text references core.features(feature_key) on delete restrict,
  membership_id uuid, starts_at timestamptz not null, expires_at timestamptz not null,
  granted_by uuid not null references auth.users(id) on delete restrict, reason text not null check(length(btrim(reason)) between 3 and 1000),
  billing_treatment text not null check(billing_treatment in ('tenant_billable','complimentary','platform_absorbed')),
  source_kind text not null default 'platform' check(source_kind in ('platform','legacy_backfill')),
  legacy_entitlement_id uuid unique references core.tenant_entitlements(id) on delete restrict,
  status text not null default 'active' check(status in ('active','suspended')),
  bill_to_tenant_id uuid references core.tenants(id) on delete restrict,
  currency char(3), unit_price_minor bigint check(unit_price_minor is null or unit_price_minor>=0),
  quota numeric(20,6) check(quota is null or quota>=0), revoked_at timestamptz,
  revoked_by uuid references auth.users(id) on delete restrict, revoke_reason text,
  created_at timestamptz not null default now(), unique(tenant_id,id),
  foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
  check((module_key is not null)::integer+(feature_key is not null)::integer=1),
  check(starts_at<expires_at),
  check((billing_treatment='tenant_billable' and bill_to_tenant_id=tenant_id and currency is not null and unit_price_minor is not null)
     or (billing_treatment<>'tenant_billable' and bill_to_tenant_id is null)),
  check((revoked_at is null and revoked_by is null and revoke_reason is null)
     or (revoked_at is not null and revoked_by is not null and revoke_reason is not null)),
  check((source_kind='legacy_backfill')=(legacy_entitlement_id is not null))
);
-- Preserve the legacy module switch's state, expiry, creator, and timestamp.
-- Legacy rows have no approved billing terms, so they are explicitly marked
-- complimentary during transition instead of inventing a price or dropping access.
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,
 source_kind,legacy_entitlement_id,status,created_at)
select e.tenant_id,e.module_key,e.created_at,coalesce(e.valid_to,'infinity'::timestamptz),e.changed_by,
 'Compatibility backfill of legacy module entitlement; no historic billing terms inferred.',
 'complimentary','legacy_backfill',e.id,e.status,e.created_at
from core.tenant_entitlements e
on conflict(legacy_entitlement_id) do nothing;
create index entitlement_grants_active_idx on core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at) where revoked_at is null;
create table core.usage_events (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  beneficiary_membership_id uuid not null, feature_key text not null references core.features(feature_key) on delete restrict,
  grant_id uuid references core.entitlement_grants(id) on delete restrict, payer_tenant_id uuid references core.tenants(id) on delete restrict,
  billing_treatment text not null check(billing_treatment in ('tenant_billable','complimentary','platform_absorbed')),
  idempotency_key text not null check(length(idempotency_key) between 8 and 200), usage_unit text not null,
  quantity numeric(20,6) not null check(quantity>0), occurred_at timestamptz not null default now(),
  unit_price_minor bigint check(unit_price_minor is null or unit_price_minor>=0), currency char(3), metadata jsonb not null default '{}'::jsonb,
  foreign key(tenant_id,beneficiary_membership_id) references iam.memberships(tenant_id,id) on delete restrict,
  foreign key(tenant_id,grant_id) references core.entitlement_grants(tenant_id,id) on delete restrict,
  unique(tenant_id,id), unique(tenant_id,idempotency_key), check(jsonb_typeof(metadata)='object'),
  check((billing_treatment='tenant_billable' and payer_tenant_id=tenant_id) or (billing_treatment<>'tenant_billable' and payer_tenant_id is null)),
  check(not (metadata ?| array['prompt','response','completion','token_text','secret','authorization']))
);
create table core.invoices (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  invoice_number text not null, status text not null check(status in ('draft','issued','void','paid','overdue')),
  currency char(3) not null, period_start timestamptz not null, period_end timestamptz not null,
  subtotal_minor bigint not null default 0, tax_minor bigint not null default 0, total_minor bigint not null default 0,
  issued_at timestamptz, due_at timestamptz, created_by uuid references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), unique(tenant_id,invoice_number), unique(tenant_id,id),
  check(period_start<period_end), check(subtotal_minor>=0 and tax_minor>=0 and total_minor=subtotal_minor+tax_minor)
);
create table core.invoice_items (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, invoice_id uuid not null,
  usage_event_id uuid references core.usage_events(id) on delete restrict, grant_id uuid references core.entitlement_grants(id) on delete restrict,
  subscription_item_id uuid references core.subscription_items(id) on delete restrict,
  description text not null, service_period_start timestamptz not null, service_period_end timestamptz not null,
  quantity numeric(20,6) not null check(quantity>0), unit_price_minor bigint not null check(unit_price_minor>=0),
  amount_minor bigint not null check(amount_minor>=0), currency char(3) not null,
  foreign key(tenant_id,invoice_id) references core.invoices(tenant_id,id) on delete restrict,
  foreign key(tenant_id,usage_event_id) references core.usage_events(tenant_id,id) on delete restrict,
  foreign key(tenant_id,grant_id) references core.entitlement_grants(tenant_id,id) on delete restrict,
  foreign key(tenant_id,subscription_item_id) references core.subscription_items(tenant_id,id) on delete restrict,
  check(service_period_start<service_period_end),
  check((usage_event_id is not null)::integer+(grant_id is not null)::integer+(subscription_item_id is not null)::integer<=1)
);
create unique index invoice_usage_once on core.invoice_items(usage_event_id) where usage_event_id is not null;
create table core.payments (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, invoice_id uuid not null,
  provider text not null, provider_reference text not null, status text not null check(status in ('pending','succeeded','failed','refunded')),
  amount_minor bigint not null check(amount_minor>=0), currency char(3) not null, occurred_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb, foreign key(tenant_id,invoice_id) references core.invoices(tenant_id,id) on delete restrict,
  unique(provider,provider_reference), check(jsonb_typeof(metadata)='object')
);

-- Normalized functional roles. Management level stays on memberships and is not
-- included in the assignable functional role catalog.
create table iam.roles (
  id uuid primary key default gen_random_uuid(), tenant_id uuid references core.tenants(id) on delete restrict,
  role_key text not null, label text not null, protected boolean not null default false,
  active boolean not null default true, created_by uuid references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), unique(tenant_id,id),
  check((protected and tenant_id is null) or (not protected and tenant_id is not null))
);
create unique index roles_global_key on iam.roles(role_key) where tenant_id is null;
create unique index roles_tenant_key on iam.roles(tenant_id,role_key) where tenant_id is not null;
create or replace function private.guard_operator_membership_separation() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if exists(select 1 from iam.platform_operators p where p.user_id=new.user_id) then
  raise exception 'platform operators cannot be company members' using errcode='23514'; end if;
 return new;
end $$;
create trigger operator_membership_separation before insert or update of user_id on iam.memberships
 for each row execute function private.guard_operator_membership_separation();
create or replace function private.guard_role_identity() returns trigger language plpgsql set search_path='' as $$
begin
 if new.tenant_id is distinct from old.tenant_id or new.role_key is distinct from old.role_key or new.protected is distinct from old.protected then
  raise exception 'functional role identity is immutable' using errcode='23514'; end if; return new;
end $$;
create trigger role_identity_guard before update on iam.roles for each row execute function private.guard_role_identity();
create trigger role_creator_immutable before update on iam.roles for each row execute function private.guard_immutable_fields('created_by');
create table iam.role_permissions (
  role_id uuid not null references iam.roles(id) on delete restrict,
  permission_key text not null references iam.permission_catalog(permission_key) on delete restrict,
  scope_kind text not null check(scope_kind in ('tenant','site','org_unit','assigned_task')),
  can_read boolean not null default false, can_write boolean not null default false, active boolean not null default true,
  primary key(role_id,permission_key,scope_kind), check(can_read or can_write)
);
create table iam.membership_roles (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, membership_id uuid not null,
  role_id uuid not null references iam.roles(id) on delete restrict,
  starts_at timestamptz not null default now(), ends_at timestamptz,
  granted_by uuid not null references auth.users(id) on delete restrict, revoked_at timestamptz,
  revoked_by uuid references auth.users(id) on delete restrict, revoke_reason text,
  foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
  check(ends_at is null or starts_at<ends_at),
  check((revoked_at is null and revoked_by is null and revoke_reason is null) or (revoked_at is not null and revoked_by is not null and revoke_reason is not null))
);
create unique index membership_role_active_unique on iam.membership_roles(tenant_id,membership_id,role_id)
 where revoked_at is null;
alter table iam.member_permissions add column org_unit_id uuid;
alter table iam.member_permissions add column task_id uuid;
alter table iam.member_permissions drop constraint member_permissions_scope_kind_check;
alter table iam.member_permissions add constraint member_permissions_scope_kind_check
 check(scope_kind in ('tenant','site','org_unit','assigned_task'));
alter table iam.member_permissions drop constraint member_permissions_check1;
alter table iam.member_permissions add constraint member_permissions_scope_key_check
 check ((scope_kind='site')=(site_id is not null) and (scope_kind='org_unit')=(org_unit_id is not null)
   and (task_id is null or scope_kind='assigned_task'));
alter table iam.member_permissions add constraint member_permissions_org_unit_fk
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict;
drop index iam.member_permission_unique;
create unique index member_permission_unique on iam.member_permissions
 (tenant_id,membership_id,permission_key,scope_kind,coalesce(site_id,'00000000-0000-0000-0000-000000000000'::uuid),
  coalesce(org_unit_id,'00000000-0000-0000-0000-000000000000'::uuid),coalesce(task_id,'00000000-0000-0000-0000-000000000000'::uuid));
create table iam.org_unit_access (
  tenant_id uuid not null, membership_id uuid not null, org_unit_id uuid not null,
  granted_by uuid not null references auth.users(id) on delete restrict, active boolean not null default true, created_at timestamptz not null default now(),
  primary key(tenant_id,membership_id,org_unit_id),
  foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
  foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict
);
alter table iam.task_assignments add column site_id uuid;
alter table iam.task_assignments add column org_unit_id uuid;
alter table iam.task_assignments add constraint task_assignments_site_fk foreign key(tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict;
alter table iam.task_assignments add constraint task_assignments_org_unit_fk foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict;

insert into iam.roles(tenant_id,role_key,label,protected) values
 (null,'inspector','Inspector',true),(null,'reviewer_1','Reviewer 1',true),(null,'reviewer_2','Reviewer 2',true),
 (null,'final_reviewer','Final Reviewer',true),(null,'action_owner','Action Owner',true),(null,'closure_reviewer','Closure Reviewer',true),
 (null,'form_designer','Form Designer',true),(null,'auditor','Auditor',true),(null,'safety_officer','Safety Officer',true);
-- Compatibility catalog only: grants are business functions, never management levels.
insert into iam.permission_catalog(permission_key,module_key,label,description) values
 ('hse.copilot.use','hse','Use HSE Copilot','Invoke Copilot subject to separate commercial entitlement')
on conflict(permission_key) do nothing;
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
select r.id,p.permission_key,'tenant',p.can_read,p.can_write from iam.roles r
join (values
 ('form_designer','hse.forms.read',true,false),('form_designer','hse.forms.manage',false,true),
 ('inspector','hse.forms.read',true,false),('inspector','hse.inspections.create',false,true),('inspector','hse.inspections.read',true,false),
 ('reviewer_1','hse.inspections.review.reviewer_1',false,true),('reviewer_1','hse.inspections.read',true,false),
 ('reviewer_2','hse.inspections.review.reviewer_2',false,true),('reviewer_2','hse.inspections.read',true,false),
 ('final_reviewer','hse.inspections.review.final_reviewer',false,true),('final_reviewer','hse.inspections.read',true,false),
 ('action_owner','hse.actions.read',true,false),('action_owner','hse.actions.update_assigned',false,true),
 ('closure_reviewer','hse.actions.read',true,false),('closure_reviewer','hse.actions.close_review',false,true),
 ('auditor','hse.dashboard.read',true,false),('auditor','hse.audit.read',true,false),('safety_officer','hse.dashboard.read',true,false),
 ('safety_officer','hse.findings.read',true,false),('safety_officer','hse.findings.manage',false,true),
 ('safety_officer','hse.actions.read',true,false),('safety_officer','hse.actions.manage',false,true)
) p(role_key,permission_key,can_read,can_write) on r.role_key=p.role_key and r.tenant_id is null
on conflict do nothing;
-- Existing direct grants remain the source of truth during the transition. New
-- installations seed no role assignment or tenant entitlement by default.

create or replace function private.has_module_entitlement(p_tenant_id uuid,p_module_key text)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from core.modules m where m.module_key=p_module_key and m.enabled)
 and (exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.module_key=p_module_key
      and g.membership_id is null and g.status='active' and g.revoked_at is null and g.starts_at<=now() and now()<g.expires_at)
   or exists(select 1 from core.subscriptions s join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
       join core.plan_entitlements pe on pe.id=si.plan_entitlement_id
       where s.tenant_id=p_tenant_id and pe.module_key=p_module_key and s.status in ('active','trialing')
         and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
         and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
   or exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.module_key=p_module_key
       and g.membership_id is null and g.revoked_at is null and g.starts_at<=now() and now()<g.expires_at))
$$;

create or replace function private.has_feature_entitlement(p_tenant_id uuid,p_membership_id uuid,p_feature_key text)
returns boolean language sql stable security definer set search_path='' as $$
 select f.enabled and private.has_module_entitlement(p_tenant_id,f.module_key) and (
   exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id where m.tenant_id=p_tenant_id
     and m.id=p_membership_id and m.status='active' and t.status='active') and (
   exists(select 1 from core.subscriptions s join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id
     where s.tenant_id=p_tenant_id and pe.feature_key=p_feature_key and s.status in ('active','trialing')
       and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
       and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
   or exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.feature_key=p_feature_key
     and (g.membership_id is null or g.membership_id=p_membership_id) and g.status='active' and g.revoked_at is null
     and g.starts_at<=now() and now()<g.expires_at and (g.billing_treatment<>'tenant_billable' or g.bill_to_tenant_id=p_tenant_id))
 )) from core.features f where f.feature_key=p_feature_key
$$;

create or replace function private.has_hse_permission(p_tenant_id uuid,p_membership_id uuid,p_permission text,
 p_site_id uuid,p_write boolean,p_task_kind text,p_task_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1 from (
     select rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write,null::uuid site_id,null::uuid org_unit_id,null::uuid task_id
     from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
       join iam.role_permissions rp on rp.role_id=r.id and rp.active
     where mr.tenant_id=p_tenant_id and mr.membership_id=p_membership_id
       and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
       and r.active and (r.tenant_id is null or r.tenant_id=p_tenant_id)
     union all
     select g.permission_key,g.scope_kind,g.can_read,g.can_write,g.site_id,g.org_unit_id,g.task_id
     from iam.member_permissions g where g.tenant_id=p_tenant_id and g.membership_id=p_membership_id and g.active
   ) x
   left join core.sites s on s.tenant_id=p_tenant_id and s.id=p_site_id
   where x.permission_key=p_permission and (case when p_write then x.can_write else x.can_read end)
    and (p_site_id is null or exists(select 1 from iam.site_access sa where sa.tenant_id=p_tenant_id and sa.membership_id=p_membership_id and sa.site_id=p_site_id and sa.active))
    and (x.scope_kind='tenant'
      or (x.scope_kind='site' and x.site_id=p_site_id)
      or (x.scope_kind='org_unit' and x.org_unit_id=s.org_unit_id and exists(select 1 from iam.org_unit_access oa
          where oa.tenant_id=p_tenant_id and oa.membership_id=p_membership_id and oa.org_unit_id=s.org_unit_id and oa.active))
      or (x.scope_kind='assigned_task' and p_task_id is not null and (x.task_id is null or x.task_id=p_task_id)
          and exists(select 1 from iam.task_assignments ta where ta.tenant_id=p_tenant_id and ta.membership_id=p_membership_id
            and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active and ta.site_id=p_site_id
            and (ta.org_unit_id is null or ta.org_unit_id=s.org_unit_id))))
 )
$$;

create or replace function private.can_access_hse(
 p_tenant_id uuid,p_permission text,p_site_id uuid default null,p_write boolean default false,p_task_kind text default null,p_task_id uuid default null
) returns boolean language sql stable security definer set search_path='' as $$
 select private.is_platform_operator() or exists(
  select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
    and private.has_module_entitlement(p_tenant_id,'hse')
    and (m.member_role='company_superadmin' or private.has_hse_permission(p_tenant_id,m.id,p_permission,p_site_id,p_write,p_task_kind,p_task_id)))
$$;
create or replace function private.can_access_core(p_tenant_id uuid,p_permission text,p_site_id uuid default null,p_write boolean default false)
returns boolean language sql stable security definer set search_path='' as $$
 select private.is_platform_operator() or exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
  and (m.member_role='company_superadmin' or private.has_hse_permission(p_tenant_id,m.id,p_permission,p_site_id,p_write,null,null)))
$$;
create or replace function api.can_use_feature(p_tenant_id uuid,p_feature_key text,p_permission text,p_site_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
   and private.has_feature_entitlement(m.tenant_id,m.id,p_feature_key)
   and (m.member_role='company_superadmin' or private.has_hse_permission(m.tenant_id,m.id,p_permission,p_site_id,false,null,null)))
$$;
create or replace function api.list_my_entitlements(p_tenant_id uuid)
returns table(entitlement_kind text,entitlement_key text,entitled boolean)
language plpgsql stable security definer set search_path='' as $$
declare v_membership uuid;
begin
 select m.id into v_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active';
 if v_membership is null then raise exception 'active_company_membership_required' using errcode='42501'; end if;
 return query select 'module'::text,m.module_key,private.has_module_entitlement(p_tenant_id,m.module_key) from core.modules m;
 return query select 'feature'::text,f.feature_key,private.has_feature_entitlement(p_tenant_id,v_membership,f.feature_key) from core.features f;
end $$;

-- Exact, validated task references. The task row defines its actual site and org unit.
create or replace function private.validate_task_assignment() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_site uuid; v_tenant uuid; v_org uuid;
begin
 if new.task_kind='inspection' then select tenant_id,site_id into v_tenant,v_site from hse.inspections where id=new.task_id;
 elsif new.task_kind='review' then select i.tenant_id,i.site_id into v_tenant,v_site from hse.inspections i where i.id=new.task_id;
 elsif new.task_kind='finding' then select tenant_id,site_id into v_tenant,v_site from hse.findings where id=new.task_id;
 elsif new.task_kind='action' then select tenant_id,site_id into v_tenant,v_site from hse.corrective_actions where id=new.task_id;
 elsif new.task_kind='follow_up' then select f.tenant_id,a.site_id into v_tenant,v_site from hse.follow_ups f join hse.corrective_actions a on a.tenant_id=f.tenant_id and a.id=f.action_id where f.id=new.task_id;
 end if;
 select org_unit_id into v_org from core.sites where tenant_id=v_tenant and id=v_site;
 if v_tenant is distinct from new.tenant_id or v_site is null or (new.site_id is not null and new.site_id is distinct from v_site)
   or (new.org_unit_id is not null and new.org_unit_id is distinct from v_org) then
   raise exception 'task assignment target/tenant/site mismatch' using errcode='23503';
 end if;
 new.site_id:=v_site; new.org_unit_id:=v_org; return new;
end $$;
create trigger task_assignment_target_guard before insert or update of tenant_id,task_kind,task_id,site_id,org_unit_id on iam.task_assignments
 for each row execute function private.validate_task_assignment();
update iam.task_assignments set task_id=task_id;
create or replace function private.validate_member_task_permission() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.scope_kind='assigned_task' and new.task_id is not null and not exists(select 1 from iam.task_assignments ta where ta.tenant_id=new.tenant_id
  and ta.membership_id=new.membership_id and ta.task_id=new.task_id and ta.active) then
  raise exception 'assigned_task permission requires an active validated assignment' using errcode='23503'; end if;
 return new;
end $$;
create trigger member_task_permission_guard before insert or update of scope_kind,task_id on iam.member_permissions
 for each row execute function private.validate_member_task_permission();
create or replace function private.validate_membership_role() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_role iam.roles%rowtype;
begin
 select * into v_role from iam.roles where id=new.role_id;
 if not found or (v_role.tenant_id is not null and v_role.tenant_id<>new.tenant_id) then
  raise exception 'functional role must be global or belong to the same tenant' using errcode='23503'; end if;
 return new;
end $$;
create trigger membership_role_tenant_guard before insert or update of tenant_id,membership_id,role_id on iam.membership_roles
 for each row execute function private.validate_membership_role();
create or replace function private.guard_membership_role_lifecycle() returns trigger
language plpgsql set search_path='' as $$
begin
 if new.tenant_id is distinct from old.tenant_id or new.membership_id is distinct from old.membership_id
   or new.role_id is distinct from old.role_id or new.starts_at is distinct from old.starts_at or new.granted_by is distinct from old.granted_by
   or old.revoked_at is not null or (old.ends_at is not null and old.ends_at<=now() and new.ends_at is distinct from old.ends_at) then
  raise exception 'functional role assignment history is immutable' using errcode='23514'; end if;
 return new;
end $$;
create trigger membership_role_lifecycle_guard before update on iam.membership_roles for each row execute function private.guard_membership_role_lifecycle();
create or replace function private.guard_functional_role_permissions() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_role iam.roles%rowtype; v_permission text; v_module text;
begin
 v_permission:=case when tg_op='DELETE' then old.permission_key else new.permission_key end;
 select * into v_role from iam.roles where id=case when tg_op='DELETE' then old.role_id else new.role_id end;
 if v_role.protected or v_role.tenant_id is null then raise exception 'protected functional roles cannot be edited' using errcode='42501'; end if;
 select module_key into v_module from iam.permission_catalog where permission_key=v_permission;
 if v_module is null or v_module in ('core','platform') or v_permission ~ '(member|role|permission|scope|task|subscription|entitlement|billing|operator)' then
  raise exception 'management permissions cannot be granted as functional permissions' using errcode='42501'; end if;
 if tg_op='DELETE' then return old; end if; return new;
end $$;
create trigger role_permission_guard before insert or update or delete on iam.role_permissions for each row execute function private.guard_functional_role_permissions();
create or replace function private.validate_role_permission_scope() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.scope_kind not in ('tenant','site','org_unit','assigned_task') or not (new.can_read or new.can_write) then
  raise exception 'invalid functional permission scope' using errcode='23514'; end if; return new;
end $$;

create or replace function private.validate_subscription_item() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if not exists(select 1 from core.subscriptions s join core.plan_entitlements pe on pe.plan_id=s.plan_id
   where s.id=new.subscription_id and s.tenant_id=new.tenant_id and pe.id=new.plan_entitlement_id) then
  raise exception 'subscription item does not belong to its plan and tenant' using errcode='23503'; end if; return new;
end $$;
create trigger subscription_item_guard before insert or update on core.subscription_items for each row execute function private.validate_subscription_item();

-- Read-only API compatibility: retain role as the management level and add roles.
create or replace view api.v_memberships with (security_invoker=true) as
 select m.user_id as id,m.id as "membershipId",m.tenant_id as "workspaceId",m.display_name as "displayName",m.email,
   m.member_role as role,m.status,
   coalesce((select jsonb_agg(sa.site_id order by sa.site_id) from iam.site_access sa where sa.tenant_id=m.tenant_id and sa.membership_id=m.id and sa.active),'[]'::jsonb) as "siteIds",
   m.member_role as "membershipLevel",
   coalesce((select jsonb_agg(r.role_key order by r.role_key) from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
      where mr.tenant_id=m.tenant_id and mr.membership_id=m.id and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)),'[]'::jsonb) as "functionalRoles"
 from iam.memberships m;

-- Invitation lifecycle: raw token is returned once to a trusted caller, only a
-- SHA-256 hash is stored. Company invitations cannot create Superadmins.
create table iam.invitations (
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references core.tenants(id) on delete restrict,
 email text not null check(email=lower(btrim(email)) and length(email)<=254),token_hash bytea not null unique,
 intended_level text not null check(intended_level in ('company_admin','employee')),
 invited_by uuid not null references auth.users(id) on delete restrict,created_at timestamptz not null default now(),expires_at timestamptz not null,
 accepted_at timestamptz,accepted_by uuid references auth.users(id) on delete restrict,revoked_at timestamptz,
 revoked_by uuid references auth.users(id) on delete restrict,revoke_reason text,
 check(expires_at>created_at),check((accepted_at is null)=(accepted_by is null)),check(accepted_at is null or revoked_at is null),
 check((revoked_at is null and revoked_by is null and revoke_reason is null) or (revoked_at is not null and revoked_by is not null and revoke_reason is not null))
);
create unique index invitation_one_pending on iam.invitations(tenant_id,email) where accepted_at is null and revoked_at is null;
create or replace function api.create_invitation(p_tenant_id uuid,p_email text,p_level text,p_actor_user_id uuid,p_ttl interval default interval '7 days')
returns table(invitation_id uuid,token text) language plpgsql security definer set search_path='' as $$
declare v_token text:=encode(extensions.gen_random_bytes(32),'hex'); v_id uuid;
begin
 if not exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id where m.tenant_id=p_tenant_id
      and m.user_id=p_actor_user_id and m.member_role='company_superadmin' and m.status='active' and t.status='active')
   or p_level not in ('company_admin','employee')
   or p_ttl<=interval '0' or p_ttl>interval '30 days' then raise exception 'invitation_not_allowed' using errcode='42501'; end if;
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
 values(p_tenant_id,lower(btrim(p_email)),extensions.digest(v_token,'sha256'),p_level,p_actor_user_id,now()+p_ttl) returning id into v_id;
 return query select v_id,v_token;
end $$;
create or replace function api.revoke_invitation(p_invitation_id uuid,p_reason text) returns void
language plpgsql security definer set search_path='' as $$
begin
 update iam.invitations set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=p_reason
 where id=p_invitation_id and private.can_manage_tenant(tenant_id) and accepted_at is null and revoked_at is null
   and length(btrim(coalesce(p_reason,'')))>=3;
 if not found then raise exception 'invitation_not_found_or_final' using errcode='22023'; end if;
end $$;
create or replace function api.accept_invitation(p_token text,p_auth_user_id uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_inv iam.invitations%rowtype; v_email text; v_membership uuid;
begin
 select lower(btrim(email)) into v_email from auth.users where id=p_auth_user_id and email_confirmed_at is not null;
 if p_auth_user_id is null or v_email is null or v_email='' then raise exception 'verified_auth_email_required' using errcode='42501'; end if;
 select * into v_inv from iam.invitations where token_hash=extensions.digest(p_token,'sha256') for update;
 if not found or v_inv.accepted_at is not null or v_inv.revoked_at is not null or now()>=v_inv.expires_at or v_inv.email<>v_email then
   raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 if not exists(select 1 from auth.users u where u.id=p_auth_user_id and lower(u.email)=v_email and email_confirmed_at is not null) then raise exception 'auth_email_mismatch' using errcode='42501'; end if;
 insert into iam.memberships(tenant_id,user_id,member_role,status,email) values(v_inv.tenant_id,p_auth_user_id,v_inv.intended_level,'active',v_email)
 on conflict(tenant_id,user_id) do update set member_role=excluded.member_role,status='active',email=excluded.email,updated_at=now()
 where iam.memberships.status in ('invited','ended','suspended') returning id into v_membership;
 if v_membership is null then raise exception 'membership_already_active' using errcode='23505'; end if;
 update iam.invitations set accepted_at=now(),accepted_by=p_auth_user_id where id=v_inv.id;
 return v_membership;
end $$;

-- HSE no longer is granted automatically to a newly provisioned tenant.
create or replace function api.create_tenant(p_name text,p_industry_label text,p_company_superadmin uuid) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_id uuid;
begin
 if not private.is_platform_operator() then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 if not exists(select 1 from auth.users u where u.id=p_company_superadmin)
   or exists(select 1 from iam.platform_operators p where p.user_id=p_company_superadmin) then raise exception 'company_superadmin_user_missing_or_is_operator' using errcode='22023'; end if;
 insert into core.tenants(name,industry_label,created_by) values(btrim(p_name),nullif(btrim(p_industry_label),''),auth.uid()) returning id into v_id;
 insert into iam.memberships(tenant_id,user_id,member_role,status) values(v_id,p_company_superadmin,'company_superadmin','active');
 return v_id;
end $$;
create or replace function api.manage_subowner(p_user_id uuid,p_active boolean) returns void
language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_owner() then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 if p_active and exists(select 1 from iam.memberships m where m.user_id=p_user_id) then raise exception 'subowner_cannot_be_a_company_member' using errcode='23514'; end if;
 if p_active then
  insert into iam.platform_operators(user_id,operator_role,created_by) values(p_user_id,'subowner',auth.uid())
  on conflict(user_id) do update set active=true,deactivated_at=null where iam.platform_operators.operator_role='subowner';
 else update iam.platform_operators set active=false,deactivated_at=now() where user_id=p_user_id and operator_role='subowner' and active; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(null,auth.uid(),'platform',case when p_active then 'platform.subowner.activated' else 'platform.subowner.deactivated' end,
  'platform_operator',p_user_id,jsonb_build_object('active',p_active));
end $$;
create or replace function api.publish_plan(p_plan_key text,p_version integer,p_name text,p_currency char(3),p_price_minor bigint,p_entitlements jsonb)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_plan uuid; v_item jsonb; v_module text; v_feature text;
begin
 if not private.is_platform_operator() or p_version<1 or p_price_minor<0 or jsonb_typeof(p_entitlements)<>'array' or jsonb_array_length(p_entitlements)=0 then
  raise exception 'plan_publish_not_allowed' using errcode='42501'; end if;
 insert into core.plans(plan_key,version,name,status,currency,price_minor) values(p_plan_key,p_version,p_name,'active',p_currency,p_price_minor) returning id into v_plan;
 for v_item in select value from jsonb_array_elements(p_entitlements) loop
  v_module:=nullif(v_item->>'module_key',''); v_feature:=nullif(v_item->>'feature_key','');
  if (v_module is not null)::integer+(v_feature is not null)::integer<>1 then raise exception 'plan_entitlement_requires_one_target' using errcode='22023'; end if;
  if v_module is not null and not exists(select 1 from core.modules where module_key=v_module) then raise exception 'unknown_module' using errcode='22023'; end if;
  if v_feature is not null and not exists(select 1 from core.features where feature_key=v_feature) then raise exception 'unknown_feature' using errcode='22023'; end if;
  insert into core.plan_entitlements(plan_id,module_key,feature_key,quota,usage_rate_minor,usage_currency)
  values(v_plan,v_module,v_feature,nullif(v_item->>'quota','')::numeric,nullif(v_item->>'usage_rate_minor','')::bigint,
    case when nullif(v_item->>'usage_rate_minor','') is null then null else p_currency end);
 end loop;
 if exists(select 1 from core.plan_entitlements pe join core.features f on f.feature_key=pe.feature_key
   where pe.plan_id=v_plan and not exists(select 1 from core.plan_entitlements pm where pm.plan_id=v_plan and pm.module_key=f.module_key)) then
  raise exception 'feature entitlement requires its parent module in the plan' using errcode='23514'; end if;
 return v_plan;
end $$;
create or replace function api.issue_entitlement_grant(p_tenant_id uuid,p_module_key text,p_feature_key text,p_membership_id uuid,
 p_starts_at timestamptz,p_expires_at timestamptz,p_reason text,p_billing_treatment text,p_currency char(3),p_unit_price_minor bigint,p_quota numeric default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid;
begin
 if not private.is_platform_operator() or p_starts_at>=p_expires_at
   or ((p_module_key is not null)::integer+(p_feature_key is not null)::integer<>1) then raise exception 'grant_not_allowed' using errcode='42501'; end if;
 if p_membership_id is not null and not exists(select 1 from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id) then raise exception 'grant_membership_mismatch' using errcode='23503'; end if;
 if p_feature_key is not null and not exists(select 1 from core.features f where f.feature_key=p_feature_key and f.enabled) then raise exception 'feature_disabled_or_unknown' using errcode='22023'; end if;
 insert into core.entitlement_grants(tenant_id,module_key,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment,
   bill_to_tenant_id,currency,unit_price_minor,quota)
 values(p_tenant_id,p_module_key,p_feature_key,p_membership_id,p_starts_at,p_expires_at,auth.uid(),p_reason,p_billing_treatment,
   case when p_billing_treatment='tenant_billable' then p_tenant_id end,
   case when p_billing_treatment='tenant_billable' then p_currency end,
   case when p_billing_treatment='tenant_billable' then p_unit_price_minor end,p_quota) returning id into v_id;
 return v_id;
end $$;
create or replace function api.revoke_entitlement_grant(p_grant_id uuid,p_reason text) returns void
language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_operator() or length(btrim(coalesce(p_reason,'')))<3 then raise exception 'grant_revocation_not_allowed' using errcode='42501'; end if;
 update core.entitlement_grants set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=p_reason where id=p_grant_id and revoked_at is null;
 if not found then raise exception 'grant_not_active' using errcode='22023'; end if;
end $$;
create or replace function api.set_feature_enabled(p_feature_key text,p_enabled boolean) returns void
language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_operator() then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 update core.features set enabled=p_enabled where feature_key=p_feature_key;
 if not found then raise exception 'feature_not_found' using errcode='22023'; end if;
end $$;
create or replace function api.set_module_enabled(p_module_key text,p_enabled boolean) returns void
language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_operator() then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 update core.modules set enabled=p_enabled where module_key=p_module_key;
 if not found then raise exception 'module_not_found' using errcode='22023'; end if;
end $$;
create or replace function api.update_subscription_status(p_subscription_id uuid,p_status text) returns void
language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_operator() or p_status not in ('trialing','active','past_due','suspended','canceled','expired') then
  raise exception 'subscription_update_not_allowed' using errcode='42501'; end if;
 update core.subscriptions set status=p_status,canceled_at=case when p_status='canceled' then coalesce(canceled_at,now()) else null end
 where id=p_subscription_id and (canceled_at is null or p_status='canceled');
 if not found then raise exception 'subscription_not_found_or_final' using errcode='22023'; end if;
end $$;
create or replace function api.create_subscription(p_tenant_id uuid,p_plan_id uuid,p_starts_at timestamptz,p_period_end timestamptz,
 p_currency char(3),p_items jsonb) returns uuid language plpgsql security definer set search_path='' as $$
declare v_sub uuid; v_item jsonb;
begin
 if not private.is_platform_operator() or p_starts_at>=p_period_end or jsonb_typeof(p_items)<>'array' or jsonb_array_length(p_items)=0 then
  raise exception 'subscription_not_allowed' using errcode='42501'; end if;
 if not exists(select 1 from core.plans p where p.id=p_plan_id and p.status='active') then raise exception 'plan_unavailable' using errcode='22023'; end if;
 insert into core.subscriptions(tenant_id,plan_id,status,starts_at,current_period_start,current_period_end,created_by)
 values(p_tenant_id,p_plan_id,'active',p_starts_at,p_starts_at,p_period_end,auth.uid()) returning id into v_sub;
 for v_item in select value from jsonb_array_elements(p_items) loop
  if not exists(select 1 from core.plan_entitlements pe where pe.id=(v_item->>'plan_entitlement_id')::uuid and pe.plan_id=p_plan_id) then
   raise exception 'subscription_item_not_in_plan' using errcode='22023'; end if;
  insert into core.subscription_items(tenant_id,subscription_id,plan_entitlement_id,quantity,unit_price_minor,currency,starts_at,ends_at)
  values(p_tenant_id,v_sub,(v_item->>'plan_entitlement_id')::uuid,coalesce((v_item->>'quantity')::numeric,1),
    (v_item->>'unit_price_minor')::bigint,p_currency,p_starts_at,p_period_end);
 end loop;
 if (select count(*) from core.subscription_items where subscription_id=v_sub)<>(select count(*) from core.plan_entitlements where plan_id=p_plan_id) then
  raise exception 'subscription_requires_all_plan_entitlements' using errcode='22023'; end if;
 return v_sub;
end $$;
create or replace function api.create_invoice_draft(p_tenant_id uuid,p_invoice_number text,p_currency char(3),p_period_start timestamptz,p_period_end timestamptz)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_invoice uuid;
begin
 if auth.role()<>'service_role' or p_period_start>=p_period_end then raise exception 'trusted_billing_required' using errcode='42501'; end if;
 insert into core.invoices(tenant_id,invoice_number,status,currency,period_start,period_end)
 values(p_tenant_id,p_invoice_number,'draft',p_currency,p_period_start,p_period_end) returning id into v_invoice;
 return v_invoice;
end $$;

-- Inspection guard correction: initial reviewer may approve to reviewer_2 or
-- return from submitted; preserve stale revision check in review trigger.
create or replace function private.guard_inspection_update() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_is_inspector boolean; v_is_reviewer boolean;
begin
 if private.can_manage_tenant(old.tenant_id) then return new; end if;
 v_is_inspector:=old.inspector_membership_id=private.current_membership_id(old.tenant_id)
   and private.can_access_hse(old.tenant_id,'hse.inspections.create',old.site_id,true);
 v_is_reviewer:=old.current_stage is not null and
   (private.can_access_hse(old.tenant_id,'hse.inspections.review',old.site_id,true,'review',old.id)
    or private.can_access_hse(old.tenant_id,'hse.inspections.review.'||old.current_stage,old.site_id,true,'review',old.id));
 if v_is_inspector then
  if (to_jsonb(new)-array['answers','title','status','revision','updated_at']) is distinct from (to_jsonb(old)-array['answers','title','status','revision','updated_at'])
   or not ((old.status in ('draft','returned') and new.status='submitted') or new.status=old.status)
   or (old.status not in ('draft','returned') and (new.answers is distinct from old.answers or new.title is distinct from old.title))
   or (new.current_stage is distinct from old.current_stage and not(old.status in ('draft','returned') and new.status='submitted' and new.current_stage='reviewer_1'))
   or new.revision<>old.revision+1 then raise exception 'inspection fields or transition are restricted' using errcode='42501'; end if;
  if old.status in ('draft','returned') and new.status='submitted' then new.current_stage:='reviewer_1'; new.submitted_at:=now(); end if;
 elsif v_is_reviewer then
  if (to_jsonb(new)-array['status','current_stage','revision','updated_at']) is distinct from (to_jsonb(old)-array['status','current_stage','revision','updated_at']) then
    raise exception 'reviewers can only change workflow state' using errcode='42501'; end if;
  if new.revision<>old.revision+1 or not (
   (old.status='submitted' and old.current_stage='reviewer_1' and new.status='in_review' and new.current_stage='reviewer_2')
   or (old.status in ('submitted','in_review') and new.status='returned' and new.current_stage=old.current_stage)
   or (old.status='in_review' and ((old.current_stage='reviewer_2' and new.status='in_review' and new.current_stage='final_reviewer')
      or (old.current_stage='final_reviewer' and new.status='approved' and new.current_stage=old.current_stage)))) then
   raise exception 'invalid inspection workflow transition' using errcode='23514'; end if;
 else raise exception 'insufficient_privilege' using errcode='42501'; end if;
 return new;
end $$;

-- Safer audit data: allowlisted value diffs only; DELETE uses OLD. History is append-only.
alter table audit.events add column actor_membership_id uuid references iam.memberships(id) on delete restrict;
alter table audit.events add column scope_kind text not null default 'tenant' check(scope_kind in ('tenant','platform'));
alter table audit.events add column request_id text;
update audit.events set scope_kind='platform' where tenant_id is null;
alter table audit.events add constraint audit_scope_consistent check((scope_kind='platform' and tenant_id is null) or (scope_kind='tenant' and tenant_id is not null));
create or replace function private.audit_row_change() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_old jsonb; v_new jsonb; v_row jsonb; v_tenant uuid; v_id uuid; v_diff jsonb;
begin
 v_old:=case when tg_op in ('UPDATE','DELETE') then to_jsonb(old) else '{}'::jsonb end;
 v_new:=case when tg_op in ('INSERT','UPDATE') then to_jsonb(new) else '{}'::jsonb end;
 v_row:=case when tg_op='DELETE' then v_old else v_new end;
 v_tenant:=private.path_uuid(v_row->>'tenant_id');
 if v_tenant is null and v_row ? 'role_id' then select tenant_id into v_tenant from iam.roles where id=private.path_uuid(v_row->>'role_id'); end if;
 v_id:=private.path_uuid(v_row->>'id');
 if v_id is null then v_id:=private.path_uuid(v_row->>'site_id'); end if;
 if v_id is null then v_id:=private.path_uuid(v_row->>'role_id'); end if;
 select coalesce(jsonb_object_agg(k,jsonb_build_object('before',v_old->k,'after',v_new->k)),'{}'::jsonb) into v_diff
 from unnest(array['name','status','member_role','module_key','feature_key','permission_key','scope_kind','site_id','org_unit_id','task_id','role_id','role_key','label','starts_at','ends_at','expires_at','revoked_at','revoked_by','active','can_read','can_write','title','category','revision','current_stage','decision','priority','owner_membership_id','due_at','outcome','linked_record_type','size_bytes','billing_treatment','bill_to_tenant_id','quantity','price_minor','unit_price_minor','currency','invoice_number','subtotal_minor','tax_minor','total_minor','period_start','period_end','canceled_at']) k
 where v_old->k is distinct from v_new->k and (v_old ? k or v_new ? k);
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,request_id,action_key,record_type,record_id,summary)
 values(v_tenant,auth.uid(),case when v_tenant is not null then private.current_membership_id(v_tenant) end,
   case when v_tenant is null then 'platform' else 'tenant' end,nullif(current_setting('request.headers',true)::jsonb->>'x-request-id',''),
   tg_table_schema||'.'||tg_table_name||'.'||lower(tg_op),tg_table_schema||'.'||tg_table_name,v_id,
   jsonb_build_object('operation',tg_op,'changed_fields',v_diff));
 if tg_op='DELETE' then return old; end if; return new;
end $$;
do $$ declare t text; begin
 foreach t in array array['core.tenants','core.tenant_domains','core.tenant_entitlements','core.org_units','core.sites',
  'iam.memberships','iam.site_access','iam.member_permissions','iam.task_assignments','iam.roles','iam.role_permissions',
  'iam.membership_roles','iam.org_unit_access','iam.invitations','core.features','core.plans','core.plan_entitlements',
  'core.subscriptions','core.subscription_items','core.entitlement_grants',
  'core.usage_events','core.invoices','core.invoice_items','core.payments','hse.form_templates','hse.form_versions',
  'hse.inspections','hse.inspection_reviews','hse.findings','hse.corrective_actions','hse.action_updates','hse.follow_ups','hse.evidence_files']
 loop execute format('drop trigger if exists audit_row_change on %s',t);
 execute format('create trigger audit_row_change after insert or update or delete on %s for each row execute function private.audit_row_change()',t); end loop;
end $$;
create or replace function private.guard_audit_immutable() returns trigger language plpgsql set search_path='' as $$
begin raise exception 'audit events are append-only' using errcode='42501'; end $$;
create trigger audit_events_immutable before update or delete on audit.events for each row execute function private.guard_audit_immutable();
create trigger usage_events_immutable before update or delete on core.usage_events for each row execute function private.guard_audit_immutable();
create trigger invoice_items_immutable before update or delete on core.invoice_items for each row execute function private.guard_audit_immutable();
create trigger payments_immutable before update or delete on core.payments for each row execute function private.guard_audit_immutable();
create trigger reviews_immutable before update or delete on hse.inspection_reviews for each row execute function private.guard_audit_immutable();
create trigger action_updates_immutable before update or delete on hse.action_updates for each row execute function private.guard_audit_immutable();
create trigger form_versions_immutable before update or delete on hse.form_versions for each row execute function private.guard_audit_immutable();

-- Remove hard-delete policy paths and never grant DELETE to browser roles.
drop policy org_write on core.org_units;
create policy org_insert on core.org_units for insert to authenticated with check(private.can_access_core(tenant_id,'core.structure.manage',null,true));
create policy org_update on core.org_units for update to authenticated using(private.can_access_core(tenant_id,'core.structure.manage',null,true)) with check(private.can_access_core(tenant_id,'core.structure.manage',null,true));
drop policy membership_write on iam.memberships;
create policy membership_insert on iam.memberships for insert to authenticated with check(private.can_manage_tenant(tenant_id) and member_role in ('company_admin','employee'));
create policy membership_update on iam.memberships for update to authenticated using(private.can_manage_tenant(tenant_id)) with check(private.can_manage_tenant(tenant_id));
drop policy followups_write on hse.follow_ups;
create policy followups_insert on hse.follow_ups for insert to authenticated with check(exists(select 1 from hse.corrective_actions a where a.tenant_id=follow_ups.tenant_id and a.id=follow_ups.action_id and (private.can_access_hse(follow_ups.tenant_id,'hse.actions.manage',a.site_id,true,'follow_up',follow_ups.id) or private.can_access_hse(follow_ups.tenant_id,'hse.actions.update_assigned',a.site_id,true,'follow_up',follow_ups.id))));
create policy followups_update on hse.follow_ups for update to authenticated using(exists(select 1 from hse.corrective_actions a where a.tenant_id=follow_ups.tenant_id and a.id=follow_ups.action_id and (private.can_access_hse(follow_ups.tenant_id,'hse.actions.manage',a.site_id,true,'follow_up',follow_ups.id) or private.can_access_hse(follow_ups.tenant_id,'hse.actions.update_assigned',a.site_id,true,'follow_up',follow_ups.id)))) with check(exists(select 1 from hse.corrective_actions a where a.tenant_id=follow_ups.tenant_id and a.id=follow_ups.action_id and (private.can_access_hse(follow_ups.tenant_id,'hse.actions.manage',a.site_id,true,'follow_up',follow_ups.id) or private.can_access_hse(follow_ups.tenant_id,'hse.actions.update_assigned',a.site_id,true,'follow_up',follow_ups.id))));
revoke delete on all tables in schema core,iam,hse,audit from authenticated,anon;
drop policy entitlements_insert on core.tenant_entitlements;
drop policy entitlements_update on core.tenant_entitlements;
revoke insert,update on core.tenant_entitlements from authenticated,anon;

-- RLS for new tenant-visible IAM data; commercial write paths stay platform-only.
do $$ declare q text; begin
 foreach q in array array['core.features','core.plans','core.plan_entitlements','core.subscriptions','core.subscription_items','core.entitlement_grants','core.usage_events','core.invoices','core.invoice_items','core.payments','iam.roles','iam.role_permissions','iam.membership_roles','iam.org_unit_access','iam.invitations'] loop
  execute format('alter table %s enable row level security',q); execute format('alter table %s force row level security',q);
 end loop;
end $$;
create policy features_read on core.features for select to authenticated using(enabled);
create policy plans_read on core.plans for select to authenticated using(status='active');
create policy plan_entitlements_read on core.plan_entitlements for select to authenticated using(exists(select 1 from core.plans p where p.id=plan_id and p.status='active'));
create policy subscriptions_read on core.subscriptions for select to authenticated using(private.is_platform_operator());
create policy subscription_items_read on core.subscription_items for select to authenticated using(private.is_platform_operator());
create policy grants_read on core.entitlement_grants for select to authenticated using(private.is_platform_operator());
create policy grants_insert on core.entitlement_grants for insert to authenticated with check(private.is_platform_operator() and granted_by=auth.uid());
create policy grants_update on core.entitlement_grants for update to authenticated using(private.is_platform_operator()) with check(private.is_platform_operator());
create policy usage_read on core.usage_events for select to authenticated using(private.is_platform_operator());
create policy invoices_read on core.invoices for select to authenticated using(private.is_platform_operator());
create policy invoice_items_read on core.invoice_items for select to authenticated using(private.is_platform_operator());
create policy payments_read on core.payments for select to authenticated using(private.is_platform_operator());
create policy roles_read on iam.roles for select to authenticated using(tenant_id is null or private.can_access_tenant(tenant_id));
create policy roles_insert on iam.roles for insert to authenticated with check(tenant_id is not null and private.can_manage_tenant(tenant_id) and created_by=auth.uid() and not protected);
create policy roles_update on iam.roles for update to authenticated using(tenant_id is not null and private.can_manage_tenant(tenant_id) and not protected) with check(tenant_id is not null and private.can_manage_tenant(tenant_id) and not protected);
create policy role_permissions_read on iam.role_permissions for select to authenticated using(exists(select 1 from iam.roles r where r.id=role_id and (r.tenant_id is null or private.can_access_tenant(r.tenant_id))));
create policy role_permissions_insert on iam.role_permissions for insert to authenticated with check(exists(select 1 from iam.roles r where r.id=role_id and r.tenant_id is not null and private.can_manage_tenant(r.tenant_id)));
create policy role_permissions_update on iam.role_permissions for update to authenticated using(exists(select 1 from iam.roles r where r.id=role_id and r.tenant_id is not null and private.can_manage_tenant(r.tenant_id))) with check(exists(select 1 from iam.roles r where r.id=role_id and r.tenant_id is not null and private.can_manage_tenant(r.tenant_id)));
create policy membership_roles_read on iam.membership_roles for select to authenticated using(private.can_manage_tenant(tenant_id) or membership_id=private.current_membership_id(tenant_id));
create policy membership_roles_insert on iam.membership_roles for insert to authenticated with check(private.can_manage_tenant(tenant_id) and granted_by=auth.uid());
create policy membership_roles_update on iam.membership_roles for update to authenticated using(private.can_manage_tenant(tenant_id)) with check(private.can_manage_tenant(tenant_id));
create policy org_access_read on iam.org_unit_access for select to authenticated using(private.can_manage_tenant(tenant_id) or membership_id=private.current_membership_id(tenant_id));
create policy org_access_insert on iam.org_unit_access for insert to authenticated with check(private.can_manage_tenant(tenant_id) and granted_by=auth.uid());
create policy org_access_update on iam.org_unit_access for update to authenticated using(private.can_manage_tenant(tenant_id)) with check(private.can_manage_tenant(tenant_id));
create policy invitations_read on iam.invitations for select to authenticated using(private.can_manage_tenant(tenant_id));
create policy invitations_insert on iam.invitations for insert to authenticated with check(private.can_manage_tenant(tenant_id) and invited_by=auth.uid());
create policy invitations_update on iam.invitations for update to authenticated using(private.can_manage_tenant(tenant_id)) with check(private.can_manage_tenant(tenant_id));

-- Write access is intentionally limited to management APIs / trusted server RPCs.
revoke all on core.subscriptions,core.subscription_items,core.entitlement_grants,core.usage_events,core.invoices,core.invoice_items,core.payments from authenticated,anon;
revoke all on core.plans,core.plan_entitlements,core.features,core.modules from authenticated,anon;
grant select on core.features,core.plans,core.plan_entitlements,core.subscriptions,core.subscription_items,core.entitlement_grants,core.usage_events,core.invoices,core.invoice_items,core.payments to authenticated;
grant select on core.modules to authenticated;
grant select on iam.roles,iam.role_permissions,iam.membership_roles,iam.org_unit_access,iam.invitations to authenticated;
grant insert,update on iam.roles,iam.role_permissions,iam.membership_roles,iam.org_unit_access to authenticated;
revoke all on function private.has_module_entitlement(uuid,text),private.has_feature_entitlement(uuid,uuid,text),private.has_hse_permission(uuid,uuid,text,uuid,boolean,text,uuid),private.validate_task_assignment(),private.validate_member_task_permission(),private.audit_row_change(),private.guard_audit_immutable() from public,anon,authenticated;
revoke all on function private.validate_membership_role(),private.guard_functional_role_permissions(),private.validate_role_permission_scope(),private.validate_subscription_item(),private.guard_role_identity(),private.guard_operator_membership_separation(),private.guard_membership_role_lifecycle() from public,anon,authenticated;
grant execute on function api.revoke_invitation(uuid,text) to authenticated;
revoke all on function api.can_use_feature(uuid,text,text,uuid),api.list_my_entitlements(uuid),api.create_invitation(uuid,text,text,uuid,interval),api.accept_invitation(text,uuid) from public,anon,authenticated;
grant execute on function api.can_use_feature(uuid,text,text,uuid) to authenticated;
grant execute on function api.list_my_entitlements(uuid) to authenticated;
grant execute on function api.create_invitation(uuid,text,text,uuid,interval),api.accept_invitation(text,uuid) to service_role;
-- Acceptance requires a verified Auth email; sending the returned token remains a trusted-backend task.
grant execute on function api.issue_entitlement_grant(uuid,text,text,uuid,timestamptz,timestamptz,text,text,char,bigint,numeric),api.revoke_entitlement_grant(uuid,text) to authenticated;
revoke all on function api.issue_entitlement_grant(uuid,text,text,uuid,timestamptz,timestamptz,text,text,char,bigint,numeric),api.revoke_entitlement_grant(uuid,text) from public,anon;
revoke all on function api.manage_subowner(uuid,boolean),api.publish_plan(text,integer,text,char,bigint,jsonb),api.create_subscription(uuid,uuid,timestamptz,timestamptz,char,jsonb),api.set_feature_enabled(text,boolean),api.set_module_enabled(text,boolean),api.update_subscription_status(uuid,text) from public,anon;
grant execute on function api.manage_subowner(uuid,boolean),api.publish_plan(text,integer,text,char,bigint,jsonb),api.create_subscription(uuid,uuid,timestamptz,timestamptz,char,jsonb),api.set_feature_enabled(text,boolean),api.set_module_enabled(text,boolean),api.update_subscription_status(uuid,text) to authenticated;
revoke all on function api.revoke_invitation(uuid,text) from public,anon;
revoke all on function api.create_invoice_draft(uuid,text,char,timestamptz,timestamptz),api.invoice_usage_event(uuid,uuid,text) from public,anon,authenticated;
grant execute on function api.create_invoice_draft(uuid,text,char,timestamptz,timestamptz),api.invoice_usage_event(uuid,uuid,text) to service_role;
create or replace function api.record_feature_usage(p_tenant_id uuid,p_membership_id uuid,p_feature_key text,p_idempotency_key text,
 p_quantity numeric,p_usage_unit text,p_metadata jsonb default '{}'::jsonb)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid; v_existing core.usage_events%rowtype; v_grant core.entitlement_grants%rowtype; v_grant_id uuid;
 v_cap numeric; v_used numeric; v_rate bigint; v_ccy char(3); v_treatment text:='tenant_billable'; v_period_start timestamptz;
begin
 if auth.role()<>'service_role' or p_quantity<=0 or p_idempotency_key is null or length(p_idempotency_key) not between 8 and 200
   or coalesce(p_metadata,'{}'::jsonb) ?| array['prompt','response','completion','token_text','secret','authorization'] then
   raise exception 'trusted_usage_recording_required' using errcode='42501'; end if;
 if not private.has_feature_entitlement(p_tenant_id,p_membership_id,p_feature_key) then raise exception 'feature_not_entitled' using errcode='42501'; end if;
 select * into v_grant from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.feature_key=p_feature_key
   and (g.membership_id=p_membership_id or g.membership_id is null) and g.status='active' and g.revoked_at is null and g.starts_at<=now() and now()<g.expires_at
 order by (g.membership_id is not null) desc,g.starts_at desc,g.id limit 1;
 if found then v_grant_id:=v_grant.id; v_cap:=v_grant.quota;
  v_treatment:=v_grant.billing_treatment; if v_treatment='tenant_billable' then v_rate:=v_grant.unit_price_minor; v_ccy:=v_grant.currency; end if;
 else
  select pe.quota,pe.usage_rate_minor,pe.usage_currency,s.current_period_start into v_cap,v_rate,v_ccy,v_period_start
  from core.subscriptions s join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
  join core.plan_entitlements pe on pe.id=si.plan_entitlement_id
  where s.tenant_id=p_tenant_id and pe.feature_key=p_feature_key and s.status in ('active','trialing')
    and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
    and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at) limit 1;
  v_treatment:='tenant_billable';
 end if;
 perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text||':'||p_feature_key||':'||case when v_grant_id is null then 'tenant' else coalesce(v_grant.membership_id::text,'tenant') end,0));
 if v_cap is not null then
  if v_grant_id is not null then select coalesce(sum(quantity),0) into v_used from core.usage_events where grant_id=v_grant_id;
  else select coalesce(sum(quantity),0) into v_used from core.usage_events where tenant_id=p_tenant_id and feature_key=p_feature_key and occurred_at>=coalesce(v_period_start,'-infinity'::timestamptz); end if;
  if v_used+p_quantity>v_cap then raise exception 'grant_usage_quota_exceeded' using errcode='54000'; end if; end if;
 insert into core.usage_events(tenant_id,beneficiary_membership_id,feature_key,grant_id,payer_tenant_id,billing_treatment,idempotency_key,usage_unit,quantity,unit_price_minor,currency,metadata)
 values(p_tenant_id,p_membership_id,p_feature_key,v_grant_id,case when v_treatment='tenant_billable' then p_tenant_id end,v_treatment,p_idempotency_key,p_usage_unit,p_quantity,v_rate,v_ccy,coalesce(p_metadata,'{}'::jsonb))
 on conflict(tenant_id,idempotency_key) do nothing
 returning id into v_id;
 if v_id is null then
  select * into v_existing from core.usage_events where tenant_id=p_tenant_id and idempotency_key=p_idempotency_key;
  if v_existing.beneficiary_membership_id<>p_membership_id or v_existing.feature_key<>p_feature_key or v_existing.quantity<>p_quantity then
   raise exception 'idempotency_key_payload_conflict' using errcode='23505'; end if;
  return v_existing.id;
 end if;
 return v_id;
end $$;
revoke all on function api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb) from public,anon,authenticated;
grant execute on function api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb) to service_role;
create or replace function api.invoice_usage_event(p_usage_event_id uuid,p_invoice_id uuid,p_description text) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_usage core.usage_events%rowtype; v_invoice core.invoices%rowtype; v_item uuid; v_amount bigint;
begin
 if auth.role()<>'service_role' then raise exception 'trusted_billing_required' using errcode='42501'; end if;
 select * into v_usage from core.usage_events where id=p_usage_event_id for update;
 if not found then raise exception 'usage_event_not_found' using errcode='22023'; end if;
 select * into v_invoice from core.invoices where id=p_invoice_id for update;
 if not found then raise exception 'invoice_not_found' using errcode='22023'; end if;
 if v_usage.payer_tenant_id is null or v_usage.tenant_id<>v_usage.payer_tenant_id or v_invoice.tenant_id<>v_usage.payer_tenant_id or v_invoice.status<>'draft'
  or v_usage.unit_price_minor is null or v_usage.currency is null or v_invoice.currency<>v_usage.currency then
  raise exception 'usage_event_not_invoiceable' using errcode='22023'; end if;
 v_amount:=ceil(v_usage.quantity*v_usage.unit_price_minor)::bigint;
 insert into core.invoice_items(tenant_id,invoice_id,usage_event_id,description,service_period_start,service_period_end,quantity,unit_price_minor,amount_minor,currency)
 values(v_invoice.tenant_id,v_invoice.id,v_usage.id,p_description,v_usage.occurred_at,v_usage.occurred_at+interval '1 microsecond',v_usage.quantity,v_usage.unit_price_minor,v_amount,v_usage.currency)
 on conflict(usage_event_id) where usage_event_id is not null do nothing returning id into v_item;
 if v_item is not null then update core.invoices set subtotal_minor=subtotal_minor+v_amount,total_minor=total_minor+v_amount where id=v_invoice.id; end if;
 return v_item;
end $$;
revoke all on function api.invoice_usage_event(uuid,uuid,text) from public,anon,authenticated;
grant execute on function api.invoice_usage_event(uuid,uuid,text) to service_role;
grant usage on schema core,iam,api to authenticated;
grant usage on schema api to service_role;
grant select on api.v_memberships to authenticated;

commit;
