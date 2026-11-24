-- 040: Dynamic member permissions and individual entitlement overrides.
--
-- Three independent layers, each evaluated server-side:
--   1. Company subscription (plans, subscription items, tenant-level grants).
--   2. Individual member entitlements: core.entitlement_grants rows scoped to one
--      membership and exactly one module OR feature, with can_use (default true),
--      can_delegate (default false), start, optional expiry (NULL = permanent),
--      reason, grantor and revocation. can_use=false is a personal restriction of
--      an existing company entitlement (Operation A). can_use=true on something the
--      company lacks is a personal exception (Operation B). They are different
--      rows with different RPCs; there is no single on/off switch.
--   3. Functional permissions: Default / Allow / Deny decisions. Deny wins.
-- Company Superadmin default is every enabled catalog permission that passes the
-- entitlement gate for that member, present and future, minus explicit Deny
-- decisions. No module, feature or permission key is named in this file.
--
-- Applying this migration is a separate, explicitly approved step.

-- ---------------------------------------------------------------------------
-- Layer 2: individual entitlement grants
-- ---------------------------------------------------------------------------
alter table core.entitlement_grants
  add column can_use boolean not null default true,
  add column can_delegate boolean not null default false,
  add column delegated_from_grant_id uuid,
  add column delegated_by uuid references auth.users(id) on delete restrict;

alter table core.entitlement_grants alter column expires_at drop not null;
alter table core.entitlement_grants drop constraint entitlement_grants_module_tenant_scope;

alter table core.entitlement_grants
  add constraint entitlement_grants_delegated_from_fk
    foreign key (tenant_id, delegated_from_grant_id) references core.entitlement_grants(tenant_id,id) on delete restrict,
  add constraint entitlement_grants_delegate_needs_use check (not can_delegate or can_use),
  add constraint entitlement_grants_delegate_is_personal check (not can_delegate or membership_id is not null),
  add constraint entitlement_grants_restriction_is_personal
    check (can_use or (membership_id is not null and billing_treatment<>'tenant_billable')),
  add constraint entitlement_grants_delegated_shape
    check (delegated_from_grant_id is null
      or (membership_id is not null and delegated_by is not null and can_use and not can_delegate));

-- Origin marker: a decision written through the platform operator RPC cannot be
-- cleared, replaced, shortened or bypassed by anything a company Superadmin can call.
alter table iam.member_permission_decisions add column protected_origin boolean not null default false;

create index entitlement_grants_member_idx on core.entitlement_grants(tenant_id,membership_id)
  where membership_id is not null;
create index entitlement_grants_delegated_from_idx on core.entitlement_grants(delegated_from_grant_id)
  where delegated_from_grant_id is not null;

-- ---------------------------------------------------------------------------
-- Entitlement evaluation (single source of truth for modules and features)
-- ---------------------------------------------------------------------------
-- A grant is live when active, started, unexpired, unrevoked and, if delegated,
-- its parent is itself live, holds can_delegate, is held by an active member and
-- the child does not outlive the parent.
create or replace function private.entitlement_grant_live(p_grant_id uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(select 1 from core.entitlement_grants g
  where g.id=p_grant_id and g.status='active' and g.revoked_at is null and g.starts_at<=now()
    and (g.expires_at is null or now()<g.expires_at)
    and (g.delegated_from_grant_id is null or exists(
      select 1 from core.entitlement_grants p
      join iam.memberships pm on pm.tenant_id=p.tenant_id and pm.id=p.membership_id and pm.status='active'
      where p.tenant_id=g.tenant_id and p.id=g.delegated_from_grant_id and p.delegated_from_grant_id is null
        and p.can_use and p.can_delegate and p.status='active' and p.revoked_at is null and p.starts_at<=now()
        and (p.expires_at is null or now()<p.expires_at)
        and (p.expires_at is null or (g.expires_at is not null and g.expires_at<=p.expires_at))
        and p.module_key is not distinct from g.module_key and p.feature_key is not distinct from g.feature_key
        and not exists(select 1 from core.entitlement_grants r
          where r.tenant_id=p.tenant_id and r.membership_id=p.membership_id and not r.can_use
            and r.status='active' and r.revoked_at is null and r.starts_at<=now() and (r.expires_at is null or now()<r.expires_at)
            and (r.module_key=coalesce(g.module_key,(select f.module_key from core.features f where f.feature_key=g.feature_key))
              or (r.feature_key is not null and r.feature_key=g.feature_key))))))
$$;

-- Company-level module entitlement (subscription or tenant-wide grant). Unchanged
-- meaning; permanent grants (NULL expiry) are now honoured.
create or replace function private.has_module_entitlement(p_tenant_id uuid, p_module_key text)
 returns boolean language sql stable security definer set search_path to '' as $$
 select exists(select 1 from core.tenants t join core.modules m on m.module_key=p_module_key and m.enabled
   where t.id=p_tenant_id and t.status='active')
 and (
   exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.module_key=p_module_key
     and g.membership_id is null and g.can_use and g.status='active' and g.revoked_at is null
     and g.starts_at<=now() and (g.expires_at is null or now()<g.expires_at))
   or exists(select 1 from core.subscriptions s
     join core.plans p on p.id=s.plan_id and p.status='active'
     join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
     where s.tenant_id=p_tenant_id and pe.module_key=p_module_key and s.status in ('active','trialing')
       and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
       and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
 );
$$;

-- State of one module for one member: restricted | company | personal_exception | none.
-- A live personal restriction wins over everything (deny precedence).
create or replace function private.member_module_state(p_tenant uuid, p_membership uuid, p_module text) returns text
language sql stable security definer set search_path='' as $$
 select case
  when not exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
      join core.modules mo on mo.module_key=p_module and mo.enabled
      where m.tenant_id=p_tenant and m.id=p_membership and m.status='active' and t.status='active') then 'none'
  when exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant and g.membership_id=p_membership
      and g.module_key=p_module and not g.can_use and private.entitlement_grant_live(g.id)) then 'restricted'
  when private.has_module_entitlement(p_tenant,p_module) then 'company'
  when exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant and g.membership_id=p_membership
      and g.module_key=p_module and g.can_use and private.entitlement_grant_live(g.id)) then 'personal_exception'
  else 'none' end
$$;

-- State of one feature for one member. A feature needs module access for that
-- member (company or personal) and is itself restricted / company / personal.
create or replace function private.member_feature_state(p_tenant uuid, p_membership uuid, p_feature text) returns text
language plpgsql stable security definer set search_path='' as $$
declare f core.features%rowtype; v_ms text;
begin
 select * into f from core.features where feature_key=p_feature;
 if f.feature_key is null or not f.enabled then return 'none'; end if;
 v_ms:=private.member_module_state(p_tenant,p_membership,f.module_key);
 if v_ms in ('none','restricted') then return v_ms; end if;
 if exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant and g.membership_id=p_membership
    and g.feature_key=p_feature and not g.can_use and private.entitlement_grant_live(g.id)) then return 'restricted'; end if;
 if exists(select 1 from core.subscriptions s
       join core.plans p on p.id=s.plan_id and p.status='active'
       join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
       join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
       where s.tenant_id=p_tenant and pe.feature_key=p_feature and s.status in ('active','trialing')
         and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
         and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
    or exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant and g.feature_key=p_feature
       and g.membership_id is null and g.can_use and private.entitlement_grant_live(g.id)
       and (g.billing_treatment<>'tenant_billable' or g.bill_to_tenant_id=p_tenant)) then return 'company'; end if;
 if exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant and g.membership_id=p_membership
    and g.feature_key=p_feature and g.can_use and private.entitlement_grant_live(g.id)
    and (g.billing_treatment<>'tenant_billable' or g.bill_to_tenant_id=p_tenant)) then return 'personal_exception'; end if;
 return 'none';
end $$;

create or replace function private.has_member_module_entitlement(p_tenant uuid, p_membership uuid, p_module text) returns boolean
language sql stable security definer set search_path='' as $$
 select private.member_module_state(p_tenant,p_membership,p_module) in ('company','personal_exception')
$$;

create or replace function private.has_feature_entitlement(p_tenant_id uuid, p_membership_id uuid, p_feature_key text)
 returns boolean language sql stable security definer set search_path to '' as $$
 select private.member_feature_state(p_tenant_id,p_membership_id,p_feature_key) in ('company','personal_exception')
$$;

-- A member may hand a permission on to others only if their own access to the
-- permission's entitlement is company-provided, or their personal exception was
-- issued with can_delegate. (Replaces the capability-limit based check.)
create or replace function private.personal_feature_delegable(p_tenant uuid, p_membership uuid, p_permission text)
 returns boolean language sql stable security definer set search_path to '' as $$
 select case
  when c.permission_key is null then false
  when (case when c.feature_key is not null then private.member_feature_state(p_tenant,p_membership,c.feature_key)
             else private.member_module_state(p_tenant,p_membership,c.module_key) end)='company' then true
  when (case when c.feature_key is not null then private.member_feature_state(p_tenant,p_membership,c.feature_key)
             else private.member_module_state(p_tenant,p_membership,c.module_key) end)='personal_exception' then
   exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant and g.membership_id=p_membership
     and g.can_use and g.can_delegate and private.entitlement_grant_live(g.id)
     and ((c.feature_key is not null and g.feature_key=c.feature_key) or (c.feature_key is null and g.module_key=c.module_key)))
  else false end
 from (select 1) one left join iam.permission_catalog c on c.permission_key=p_permission
$$;

revoke all on function private.entitlement_grant_live(uuid), private.member_module_state(uuid,uuid,text),
 private.member_feature_state(uuid,uuid,text), private.has_member_module_entitlement(uuid,uuid,text)
 from public,anon,authenticated,service_role;

-- ---------------------------------------------------------------------------
-- Platform powers
-- ---------------------------------------------------------------------------
insert into iam.platform_permission_catalog(permission_key) values ('member.permissions'),('member.entitlements')
 on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Operator-aware decision triggers (validated actor via transaction-local setting)
-- ---------------------------------------------------------------------------
create or replace function private.operator_decision_actor() returns uuid
language plpgsql stable security definer set search_path='' as $$
declare v uuid:=nullif(current_setting('sentriq.operator_decision_actor',true),'')::uuid;
begin
 if v is not null and v=auth.uid() and exists(select 1 from iam.platform_operators o where o.user_id=v and o.active)
    and private.platform_permission_allowed('member.permissions',v) then return v; end if;
 return null;
end $$;
revoke all on function private.operator_decision_actor() from public,anon,authenticated,service_role;

create or replace function private.guard_decision_authority() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if private.operator_decision_actor() is not null then return new; end if;
 if tg_op='INSERT' and new.protected_origin then
  raise exception 'protected_origin_requires_operator' using errcode='42501'; end if;
 if tg_op='INSERT' and new.decision='deny' and new.scope_kind='tenant'
  and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_restriction_deny',true)='on'
  and new.reason like 'Superadmin invitation restriction:%' then return new; end if;
 if tg_op='INSERT' then
  perform private.assert_permission_grantable(new.tenant_id,new.permission_key,new.can_write,new.site_id,new.org_unit_id,new.task_kind,new.task_id);
 else
  if new.protected_origin is distinct from old.protected_origin then
   raise exception 'protected_origin_requires_operator' using errcode='42501'; end if;
  if old.protected_origin and (new.status is distinct from old.status or new.decision is distinct from old.decision
     or new.starts_at is distinct from old.starts_at or new.ends_at is distinct from old.ends_at
     or new.can_read is distinct from old.can_read or new.can_write is distinct from old.can_write) then
   raise exception 'operator_decision_requires_operator' using errcode='42501'; end if;
  if old.decision='deny' and old.status='active' and new.status<>'active' then
   if exists(select 1 from iam.memberships m where m.tenant_id=old.tenant_id and m.id=old.membership_id
        and m.user_id=private.request_actor_id()) then
    raise exception 'own_restriction_cannot_be_cleared' using errcode='42501'; end if;
   if old.granted_by is distinct from private.request_actor_id() and not private.can_manage_tenant(old.tenant_id) then
    raise exception 'deny_removal_requires_creator_or_superadmin' using errcode='42501'; end if;
  end if;
 end if;
 return new;
end $$;

create or replace function private.capture_decision_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if tg_op='INSERT' and new.decision='deny' and new.scope_kind='tenant'
  and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_restriction_deny',true)='on'
  and new.reason like 'Superadmin invitation restriction:%' then return new; end if;
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id or new.granted_by is distinct from old.granted_by
   or new.membership_id is distinct from old.membership_id or new.tenant_id is distinct from old.tenant_id
   or new.permission_key is distinct from old.permission_key then
   raise exception 'decision_origin_is_immutable' using errcode='23514';
  end if;
  return new;
 end if;
 if private.operator_decision_actor() is not null and new.granted_by=private.operator_decision_actor() then return new; end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=new.granted_by and status='active';
 if m.id is null then raise exception 'active_decision_grantor_required' using errcode='42501'; end if;
 if m.member_role<>'company_superadmin' then
  select d.id into new.source_delegation_id from iam.delegation_envelopes d
   where d.tenant_id=new.tenant_id and d.delegate_membership_id=m.id
    and 'direct_permission_decision'=any(d.allowed_capabilities)
    and private.decision_source_valid(d.id,d.tenant_id)
    and (d.level='tenant' or (d.level='employees_default' and exists(select 1 from iam.memberships target
      where target.tenant_id=new.tenant_id and target.id=new.membership_id and target.member_role='employee'))
     or (d.level='site' and new.scope_kind='site' and d.site_id=new.site_id)
     or (d.level='org_unit' and new.scope_kind='org_unit' and d.org_unit_id=new.org_unit_id))
   order by d.created_at desc,d.id limit 1;
  if new.source_delegation_id is null then raise exception 'exact_decision_envelope_required' using errcode='42501'; end if;
 end if;
 return new;
end $$;

-- ---------------------------------------------------------------------------
-- Operator RPCs
-- ---------------------------------------------------------------------------
-- Functional permission decision for any member, including Company Superadmin.
-- choice: default (clear), allow, deny. Allow never creates entitlement: it is
-- refused unless the target already passes the entitlement gate. Platform power
-- member.permissions; the actor is auth.uid(), never a client-supplied id.
create or replace function api.platform_set_member_decision(
 p_tenant_id uuid, p_membership_id uuid, p_permission_key text, p_choice text, p_reason text,
 p_scope_kind text default 'tenant', p_site_id uuid default null, p_org_unit_id uuid default null,
 p_ends_at timestamptz default null, p_can_read boolean default true, p_can_write boolean default true
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_target iam.memberships%rowtype; c iam.permission_catalog%rowtype; v_id uuid;
begin
 if v_actor is null or not private.is_platform_operator() or not private.platform_permission_allowed('member.permissions')
  or p_choice not in ('default','allow','deny') or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or p_scope_kind not in ('tenant','site','org_unit')
  or (p_scope_kind='site') is distinct from (p_site_id is not null)
  or (p_scope_kind='org_unit') is distinct from (p_org_unit_id is not null)
  or (p_ends_at is not null and p_ends_at<=now())
  or (p_choice='allow' and not (coalesce(p_can_read,false) or coalesce(p_can_write,false))) then
  raise exception 'platform_member_decision_not_authorized' using errcode='42501';
 end if;
 select * into v_target from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and status='active';
 if v_target.id is null or v_target.user_id=v_actor
   or not exists(select 1 from core.tenants where id=p_tenant_id and status='active') then
  raise exception 'platform_member_decision_target_invalid' using errcode='22023'; end if;
 select * into c from iam.permission_catalog where permission_key=p_permission_key and enabled;
 if c.permission_key is null then raise exception 'permission_key_not_in_enabled_catalog' using errcode='22023'; end if;
 if p_scope_kind='site' and not exists(select 1 from core.sites where tenant_id=p_tenant_id and id=p_site_id)
   or p_scope_kind='org_unit' and not exists(select 1 from core.org_units where tenant_id=p_tenant_id and id=p_org_unit_id) then
  raise exception 'scope_not_in_tenant' using errcode='23503'; end if;
 if p_choice='allow' and not (private.has_member_module_entitlement(p_tenant_id,p_membership_id,c.module_key)
   and (c.feature_key is null or private.has_feature_entitlement(p_tenant_id,p_membership_id,c.feature_key))) then
  raise exception 'permission_not_entitled_for_member' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-decision:'||p_tenant_id::text||':'||p_membership_id::text||':'||p_permission_key,0));
 perform set_config('sentriq.operator_decision_actor',v_actor::text,true);
 update iam.member_permission_decisions d set status='revoked',revoked_at=now(),revoked_by=v_actor,
   revoke_reason='Replaced by platform operator decision: '||btrim(p_reason)
  where d.tenant_id=p_tenant_id and d.membership_id=p_membership_id and d.permission_key=p_permission_key
    and d.scope_kind=p_scope_kind and d.site_id is not distinct from p_site_id
    and d.org_unit_id is not distinct from p_org_unit_id and d.status='active';
 if p_choice in ('allow','deny') then
  insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,org_unit_id,
    can_read,can_write,status,granted_by,ends_at,reason,protected_origin)
  values(p_tenant_id,p_membership_id,p_permission_key,p_choice,p_scope_kind,p_site_id,p_org_unit_id,
    case when p_choice='allow' then coalesce(p_can_read,false) else false end,
    case when p_choice='allow' then coalesce(p_can_write,false) else false end,
    'active',v_actor,p_ends_at,btrim(p_reason),true) returning id into v_id;
 end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,p_scope_kind,'iam.platform.member_decision.set','iam.memberships',p_membership_id,
  jsonb_build_object('permission_key',p_permission_key,'choice',p_choice,'decision_id',v_id,
   'target_role',v_target.member_role,'reason',btrim(p_reason)));
 return v_id;
end $$;

-- Individual entitlement for one member and exactly one module OR feature.
-- p_can_use=false: personal restriction of something the company has (Operation A).
-- p_can_use=true: personal exception (Operation B), works outside the subscription.
-- Platform power member.entitlements (Owner always; Subowner until withdrawn).
create or replace function api.platform_set_member_entitlement(
 p_tenant_id uuid, p_membership_id uuid, p_module_key text, p_feature_key text, p_reason text,
 p_can_use boolean default true, p_can_delegate boolean default false,
 p_starts_at timestamptz default null, p_expires_at timestamptz default null
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_target iam.memberships%rowtype; v_id uuid; v_start timestamptz:=coalesce(p_starts_at,now());
begin
 if v_actor is null or not private.is_platform_operator() or not private.platform_permission_allowed('member.entitlements')
  or ((p_module_key is not null)::integer+(p_feature_key is not null)::integer)<>1
  or p_can_use is null or p_can_delegate is null or (p_can_delegate and not p_can_use)
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or (p_expires_at is not null and p_expires_at<=v_start) then
  raise exception 'platform_member_entitlement_not_authorized' using errcode='42501';
 end if;
 select * into v_target from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and status='active';
 if v_target.id is null or v_target.user_id=v_actor
   or not exists(select 1 from core.tenants where id=p_tenant_id and status='active') then
  raise exception 'platform_member_entitlement_target_invalid' using errcode='22023'; end if;
 if p_module_key is not null and not exists(select 1 from core.modules where module_key=p_module_key and enabled) then
  raise exception 'module_disabled_or_unknown' using errcode='22023'; end if;
 if p_feature_key is not null and not exists(select 1 from core.features where feature_key=p_feature_key and enabled) then
  raise exception 'feature_disabled_or_unknown' using errcode='22023'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-member-entitlement:'||p_tenant_id::text||':'||p_membership_id::text,0));
 insert into core.entitlement_grants(tenant_id,module_key,feature_key,membership_id,starts_at,expires_at,granted_by,reason,
   billing_treatment,can_use,can_delegate)
 values(p_tenant_id,p_module_key,p_feature_key,p_membership_id,v_start,p_expires_at,v_actor,btrim(p_reason),
   'platform_absorbed',p_can_use,p_can_delegate) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,'tenant','iam.platform.member_entitlement.set','core.entitlement_grants',v_id,
  jsonb_build_object('target_membership_id',p_membership_id,'module_key',p_module_key,'feature_key',p_feature_key,
   'can_use',p_can_use,'can_delegate',p_can_delegate,'starts_at',v_start,'expires_at',p_expires_at,'reason',btrim(p_reason)));
 return v_id;
end $$;

-- Revoke a personal entitlement (exception or restriction). Delegated children are
-- revoked with it and each revocation is audited.
create or replace function api.platform_revoke_member_entitlement(p_grant_id uuid, p_reason text) returns integer
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); g core.entitlement_grants%rowtype; r record; v_n integer:=0;
begin
 if v_actor is null or not private.is_platform_operator() or not private.platform_permission_allowed('member.entitlements')
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_member_entitlement_revoke_not_authorized' using errcode='42501'; end if;
 select * into g from core.entitlement_grants where id=p_grant_id and membership_id is not null and delegated_from_grant_id is null
   and revoked_at is null for update;
 if g.id is null then raise exception 'member_entitlement_not_found_or_final' using errcode='22023'; end if;
 if exists(select 1 from iam.memberships m where m.tenant_id=g.tenant_id and m.id=g.membership_id and m.user_id=v_actor) then
  raise exception 'platform_member_entitlement_revoke_not_authorized' using errcode='42501'; end if;
 for r in select id,tenant_id from core.entitlement_grants where (id=g.id or delegated_from_grant_id=g.id) and revoked_at is null loop
  update core.entitlement_grants set revoked_at=now(),revoked_by=v_actor,revoke_reason=btrim(p_reason) where id=r.id;
  insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(r.tenant_id,v_actor,'tenant',case when r.id=g.id then 'iam.platform.member_entitlement.revoked'
    else 'iam.entitlement_delegation.revoked_with_parent' end,'core.entitlement_grants',r.id,
    jsonb_build_object('reason',btrim(p_reason),'parent_grant_id',g.id));
  v_n:=v_n+1;
 end loop;
 return v_n;
end $$;

-- ---------------------------------------------------------------------------
-- Delegation of a personal entitlement (only from a live grant with can_delegate)
-- ---------------------------------------------------------------------------
-- The delegated grant: same company, same module/feature, personal to one other
-- active member of the same company, can_use only (never can_delegate), expiry not
-- later than the source, audited. Company Superadmin status gives no right to do
-- this on its own; only a live source grant that explicitly allows it.
create or replace function api.delegate_member_entitlement(
 p_tenant_id uuid, p_source_grant_id uuid, p_target_membership_id uuid, p_reason text,
 p_expires_at timestamptz default null
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_am iam.memberships%rowtype; s core.entitlement_grants%rowtype; v_exp timestamptz; v_id uuid;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'entitlement_delegation_not_authorized' using errcode='42501'; end if;
 select m.* into v_am from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active';
 select * into s from core.entitlement_grants where id=p_source_grant_id and tenant_id=p_tenant_id;
 if v_am.id is null or s.id is null or s.membership_id is distinct from v_am.id or s.delegated_from_grant_id is not null
   or not s.can_use or not s.can_delegate or not private.entitlement_grant_live(s.id)
   or p_target_membership_id=v_am.id
   or (case when s.feature_key is not null then private.member_feature_state(p_tenant_id,v_am.id,s.feature_key)
            else private.member_module_state(p_tenant_id,v_am.id,s.module_key) end) not in ('company','personal_exception')
   or not exists(select 1 from iam.memberships tm where tm.tenant_id=p_tenant_id and tm.id=p_target_membership_id and tm.status='active') then
  raise exception 'entitlement_delegation_not_authorized' using errcode='42501'; end if;
 v_exp:=coalesce(p_expires_at,s.expires_at);
 if s.expires_at is not null and (v_exp is null or v_exp>s.expires_at) then
  raise exception 'delegation_cannot_outlive_source' using errcode='22023'; end if;
 if v_exp is not null and v_exp<=now() then raise exception 'delegation_expiry_in_past' using errcode='22023'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-member-entitlement:'||p_tenant_id::text||':'||p_target_membership_id::text,0));
 insert into core.entitlement_grants(tenant_id,module_key,feature_key,membership_id,starts_at,expires_at,granted_by,reason,
   billing_treatment,quota,can_use,can_delegate,delegated_from_grant_id,delegated_by)
 values(p_tenant_id,s.module_key,s.feature_key,p_target_membership_id,now(),v_exp,v_actor,btrim(p_reason),
   case when s.billing_treatment='tenant_billable' then 'platform_absorbed' else s.billing_treatment end,
   s.quota,true,false,s.id,v_actor) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,v_am.id,'tenant','iam.entitlement_delegation.created','core.entitlement_grants',v_id,
  jsonb_build_object('source_grant_id',s.id,'target_membership_id',p_target_membership_id,'module_key',s.module_key,
   'feature_key',s.feature_key,'expires_at',v_exp,'reason',btrim(p_reason)));
 return v_id;
end $$;

-- Revoke a delegated grant: by the delegator, by the source holder, or by an
-- operator holding member.entitlements.
create or replace function api.revoke_delegated_entitlement(p_grant_id uuid, p_reason text) returns void
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); g core.entitlement_grants%rowtype;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'entitlement_delegation_revoke_not_authorized' using errcode='42501'; end if;
 select * into g from core.entitlement_grants where id=p_grant_id and delegated_from_grant_id is not null and revoked_at is null for update;
 if g.id is null or not (g.delegated_by=v_actor
    or (private.is_platform_operator() and private.platform_permission_allowed('member.entitlements'))) then
  raise exception 'entitlement_delegation_revoke_not_authorized' using errcode='42501'; end if;
 update core.entitlement_grants set revoked_at=now(),revoked_by=v_actor,revoke_reason=btrim(p_reason) where id=g.id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(g.tenant_id,v_actor,'tenant','iam.entitlement_delegation.revoked','core.entitlement_grants',g.id,
  jsonb_build_object('reason',btrim(p_reason),'source_grant_id',g.delegated_from_grant_id));
end $$;

-- ---------------------------------------------------------------------------
-- Server-calculated effective access
-- ---------------------------------------------------------------------------
-- Two independent axes per permission plus lapsed history:
--   entitlement.state: company | personal_exception | restricted | none
--   functional.state:  deny | default_superadmin | allow | allow_scoped | inherited | none
--   effective: tenant-wide result (entitlement gate AND functional result).
-- Site/org/task-scoped rows are reported as scoped=true; they are not tenant-wide.
create or replace function api.member_effective_access(p_tenant_id uuid, p_membership_id uuid) returns jsonb
language plpgsql stable security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); t iam.memberships%rowtype; v_mods jsonb; v_feats jsonb; v_perms jsonb; v_grants jsonb;
begin
 if v_actor is null then raise exception 'effective_access_not_authorized' using errcode='42501'; end if;
 select * into t from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id;
 if t.id is null or not (private.is_platform_operator() or private.can_manage_tenant(p_tenant_id) or t.user_id=v_actor) then
  raise exception 'effective_access_not_authorized' using errcode='42501'; end if;

 select coalesce(jsonb_agg(jsonb_build_object('module_key',x.module_key,'company_entitled',x.company,
   'state',x.state) order by x.module_key),'[]'::jsonb) into v_mods
 from (select m.module_key, private.has_module_entitlement(p_tenant_id,m.module_key) company,
        private.member_module_state(p_tenant_id,p_membership_id,m.module_key) state from core.modules m where m.enabled) x;

 select coalesce(jsonb_agg(jsonb_build_object('feature_key',x.feature_key,'module_key',x.module_key,'state',x.state)
   order by x.feature_key),'[]'::jsonb) into v_feats
 from (select f.feature_key,f.module_key,private.member_feature_state(p_tenant_id,p_membership_id,f.feature_key) state
       from core.features f where f.enabled) x;

 select coalesce(jsonb_agg(jsonb_build_object('grant_id',g.id,'module_key',g.module_key,'feature_key',g.feature_key,
   'can_use',g.can_use,'can_delegate',g.can_delegate,'starts_at',g.starts_at,'expires_at',g.expires_at,
   'permanent',g.expires_at is null,'reason',g.reason,'granted_by',g.granted_by,'created_at',g.created_at,
   'delegated_from_grant_id',g.delegated_from_grant_id,'delegated_by',g.delegated_by,
   'revoked_at',g.revoked_at,'revoked_by',g.revoked_by,'revoke_reason',g.revoke_reason,
   'status',case when g.revoked_at is not null then 'revoked'
                 when g.expires_at is not null and g.expires_at<=now() then 'expired'
                 when g.starts_at>now() then 'not_started'
                 when g.status<>'active' then g.status
                 when private.entitlement_grant_live(g.id) then 'live' else 'inactive' end)
   order by g.created_at desc),'[]'::jsonb) into v_grants
 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.membership_id=p_membership_id;

 select coalesce(jsonb_agg(p.obj order by p.k),'[]'::jsonb) into v_perms from (
  select c.permission_key k, jsonb_build_object(
   'permission_key',c.permission_key,'module_key',c.module_key,'feature_key',c.feature_key,
   'entitlement_state',e.es,
   'functional_state',case
      when e.es in ('none','restricted') then 'none'
      when d.deny_id is not null then 'deny'
      when t.member_role='company_superadmin' then 'default_superadmin'
      when d.allow_id is not null then 'allow'
      when d.scoped_allow then 'allow_scoped'
      when r.tenant_wide then 'inherited'
      when r.scoped then 'inherited_scoped'
      else 'none' end,
   'effective',e.es in ('company','personal_exception') and d.deny_id is null
      and (t.member_role='company_superadmin' or d.allow_id is not null or r.tenant_wide),
   'scoped',(e.es in ('company','personal_exception') and d.deny_id is null and t.member_role<>'company_superadmin'
      and d.allow_id is null and not r.tenant_wide and (d.scoped_allow or r.scoped)),
   'decision',jsonb_build_object('deny_id',d.deny_id,'allow_id',d.allow_id,'reason',coalesce(d.deny_reason,d.allow_reason),
      'granted_by',coalesce(d.deny_by,d.allow_by),'ends_at',coalesce(d.deny_ends,d.allow_ends),
      'can_read',d.can_read,'can_write',d.can_write),
   'lapsed',(select jsonb_build_object('kind',case when x.status='revoked' then 'revoked' else 'expired' end,
        'at',coalesce(x.revoked_at,x.ends_at),'reason',coalesce(x.revoke_reason,x.reason),'decision',x.decision)
      from iam.member_permission_decisions x where x.tenant_id=p_tenant_id and x.membership_id=p_membership_id
       and x.permission_key=c.permission_key and x.scope_kind='tenant'
       and (x.status='revoked' or (x.ends_at is not null and x.ends_at<=now()))
       and not exists(select 1 from iam.member_permission_decisions y where y.tenant_id=x.tenant_id and y.membership_id=x.membership_id
         and y.permission_key=x.permission_key and y.scope_kind='tenant' and y.status='active'
         and y.starts_at<=now() and (y.ends_at is null or now()<y.ends_at))
       order by coalesce(x.revoked_at,x.ends_at) desc limit 1)
  ) obj
  from iam.permission_catalog c
  cross join lateral (select case when c.feature_key is not null
     then private.member_feature_state(p_tenant_id,p_membership_id,c.feature_key)
     else private.member_module_state(p_tenant_id,p_membership_id,c.module_key) end es) e
  cross join lateral (select
     (select x.id from iam.member_permission_decisions x where x.tenant_id=p_tenant_id and x.membership_id=p_membership_id
       and x.permission_key=c.permission_key and x.decision='deny' and x.status='active' and x.scope_kind='tenant'
       and x.starts_at<=now() and (x.ends_at is null or now()<x.ends_at) order by x.created_at desc limit 1) deny_id,
     (select x.reason from iam.member_permission_decisions x where x.id=(select x2.id from iam.member_permission_decisions x2
       where x2.tenant_id=p_tenant_id and x2.membership_id=p_membership_id and x2.permission_key=c.permission_key
       and x2.decision='deny' and x2.status='active' and x2.scope_kind='tenant' and x2.starts_at<=now()
       and (x2.ends_at is null or now()<x2.ends_at) order by x2.created_at desc limit 1)) deny_reason,
     (select x.granted_by from iam.member_permission_decisions x where x.tenant_id=p_tenant_id and x.membership_id=p_membership_id
       and x.permission_key=c.permission_key and x.decision='deny' and x.status='active' and x.scope_kind='tenant'
       and x.starts_at<=now() and (x.ends_at is null or now()<x.ends_at) order by x.created_at desc limit 1) deny_by,
     (select x.ends_at from iam.member_permission_decisions x where x.tenant_id=p_tenant_id and x.membership_id=p_membership_id
       and x.permission_key=c.permission_key and x.decision='deny' and x.status='active' and x.scope_kind='tenant'
       and x.starts_at<=now() and (x.ends_at is null or now()<x.ends_at) order by x.created_at desc limit 1) deny_ends,
     a.id allow_id,a.reason allow_reason,a.granted_by allow_by,a.ends_at allow_ends,a.can_read,a.can_write,
     exists(select 1 from iam.member_permission_decisions x where x.tenant_id=p_tenant_id and x.membership_id=p_membership_id
       and x.permission_key=c.permission_key and x.decision='allow' and x.status='active' and x.scope_kind<>'tenant'
       and x.starts_at<=now() and (x.ends_at is null or now()<x.ends_at)) scoped_allow
     from (select 1) one left join lateral (select x.* from iam.member_permission_decisions x
       where x.tenant_id=p_tenant_id and x.membership_id=p_membership_id and x.permission_key=c.permission_key
       and x.decision='allow' and x.status='active' and x.scope_kind='tenant'
       and x.starts_at<=now() and (x.ends_at is null or now()<x.ends_at) order by x.created_at desc limit 1) a on true) d
  cross join lateral (select
     exists(select 1 from iam.membership_roles mr join iam.roles ro on ro.id=mr.role_id and ro.active
        join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.role_id=mr.role_id and rv.status='published'
        join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=c.permission_key
       where mr.tenant_id=p_tenant_id and mr.membership_id=p_membership_id and mr.revoked_at is null and mr.starts_at<=now()
        and (mr.ends_at is null or now()<mr.ends_at) and rp.scope_kind='tenant')
     or exists(select 1 from iam.membership_permission_profiles mp
        join iam.permission_profile_versions pv on pv.tenant_id=mp.tenant_id and pv.id=mp.profile_version_id
        join iam.permission_profile_permissions pp on pp.tenant_id=mp.tenant_id and pp.profile_version_id=pv.id and pp.permission_key=c.permission_key
       where mp.tenant_id=p_tenant_id and mp.membership_id=p_membership_id and mp.is_current and pp.scope_kind='tenant') tenant_wide,
     exists(select 1 from iam.membership_roles mr join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.status='published'
        join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=c.permission_key
       where mr.tenant_id=p_tenant_id and mr.membership_id=p_membership_id and mr.revoked_at is null and rp.scope_kind<>'tenant')
     or exists(select 1 from iam.membership_permission_profiles mp
        join iam.permission_profile_permissions pp on pp.tenant_id=mp.tenant_id and pp.profile_version_id=mp.profile_version_id and pp.permission_key=c.permission_key
       where mp.tenant_id=p_tenant_id and mp.membership_id=p_membership_id and mp.is_current and pp.scope_kind<>'tenant') scoped) r
  where c.enabled) p;

 return jsonb_build_object('membership',jsonb_build_object('id',t.id,'role',t.member_role,'status',t.status,'user_id',t.user_id),
   'modules',v_mods,'features',v_feats,'entitlement_grants',v_grants,'permissions',v_perms,
   'calculated_at',now());
end $$;


-- ---------------------------------------------------------------------------
-- Enforcement: entitlement gate is member-aware; Superadmin default is generic
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION api.authorize(p_tenant_id uuid, p_permission_key text, p_action text, p_site_id uuid DEFAULT NULL::uuid, p_org_unit_id uuid DEFAULT NULL::uuid, p_task_kind text DEFAULT NULL::text, p_task_id uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare m iam.memberships%rowtype; c iam.permission_catalog%rowtype; v_allowed boolean;
begin
 if p_action is null then return false;end if;
 select * into m from iam.memberships where tenant_id=p_tenant_id and user_id=private.request_actor_id() and status='active';
 select * into c from iam.permission_catalog where permission_key=p_permission_key and enabled;
 if m.id is null or c.permission_key is null or not p_action=any(c.supported_actions)
  or not exists(select 1 from core.tenants where id=p_tenant_id and status='active')
  or not private.has_member_module_entitlement(p_tenant_id,m.id,c.module_key)
  or (c.feature_key is not null and not private.has_feature_entitlement(p_tenant_id,m.id,c.feature_key))
  or not private.people_scope_allowed(p_tenant_id,m.id,p_site_id,p_org_unit_id)
  or (p_site_id is not null and not exists(select 1 from core.sites where tenant_id=p_tenant_id and id=p_site_id
    and (p_org_unit_id is null or org_unit_id=p_org_unit_id)))
  or (p_task_id is not null and not exists(select 1 from iam.task_assignments where tenant_id=p_tenant_id
    and membership_id=m.id and task_kind=p_task_kind and task_id=p_task_id and active
    and (site_id is null or site_id=p_site_id) and (org_unit_id is null or org_unit_id=p_org_unit_id))) then return false; end if;
 -- Legacy read/write grants retain only their original explicit meaning.
 if p_action in ('read','write') then
  return private.phase1_permission_allowed(p_tenant_id,p_permission_key,p_site_id,p_org_unit_id,p_action='write',p_task_kind,p_task_id);
 end if;
 if exists(select 1 from iam.member_permission_decisions d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)
   and not (d.scope_kind='tenant' and not coalesce(d.protected_origin,false) and private.valid_specific_override(p_tenant_id,m.id,p_permission_key,p_site_id,p_org_unit_id,p_task_kind,p_task_id))) then return false; end if;
 if exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)
   and not (d.scope_kind='tenant' and private.valid_specific_override(p_tenant_id,m.id,p_permission_key,p_site_id,p_org_unit_id,p_task_kind,p_task_id))) then return false; end if;
 if m.member_role='company_superadmin' then
  -- Company Superadmin default: every enabled catalog permission that passed the
  -- entitlement and scope gates above, minus explicit Deny decisions (checked above).
  return true;
 end if;
 return private.functional_action_allowed(p_tenant_id,m.id,p_permission_key,p_action,p_site_id,p_org_unit_id,p_task_kind,p_task_id) or exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='allow' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id));
end $function$;

CREATE OR REPLACE FUNCTION private.phase1_permission_allowed(p_tenant_id uuid, p_permission_key text, p_site_id uuid DEFAULT NULL::uuid, p_org_unit_id uuid DEFAULT NULL::uuid, p_write boolean DEFAULT false, p_task_kind text DEFAULT NULL::text, p_task_id uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 with actor as (
   select m.id,m.member_role from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and private.has_member_module_entitlement(p_tenant_id,m.id,(select module_key from iam.permission_catalog where permission_key=p_permission_key))
 ), catalog as (
   select pc.permission_key,pc.enabled,pc.feature_key from iam.permission_catalog pc
    where pc.permission_key=p_permission_key 
 ), grants as (
   select rp.scope_kind,null::uuid site_id,null::uuid org_unit_id,mr.id assignment_id,null::text task_kind,null::uuid task_id
   from actor a join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.active
   join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.role_id=mr.role_id and rv.status='published'
   join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=p_permission_key
   where r.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and rv.role_family=r.role_family and private.decision_source_valid(mr.source_delegation_id,mr.tenant_id) and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select pp.scope_kind,pp.site_id,pp.org_unit_id,null::uuid,null::text,null::uuid
   from actor a join iam.membership_permission_profiles mp on mp.tenant_id=p_tenant_id and mp.membership_id=a.id and mp.is_current and private.decision_source_valid(mp.source_delegation_id,mp.tenant_id)
   join iam.permission_profiles p on p.tenant_id=mp.tenant_id and p.id=mp.profile_id and p.active and p.role_family=mp.role_family
   join iam.permission_profile_versions pv on pv.tenant_id=mp.tenant_id and pv.id=mp.profile_version_id and pv.profile_id=p.id
   join iam.permission_profile_permissions pp on pp.tenant_id=p.tenant_id and pp.profile_version_id=pv.id and pp.permission_key=p_permission_key
   where mp.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and (case when p_write then pp.can_write else pp.can_read or pp.can_write end)
   union all
   select d.scope_kind,d.site_id,d.org_unit_id,null::uuid,d.task_kind,d.task_id
   from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='allow' and d.status='active'
     and private.decision_source_valid(d.source_delegation_id,d.tenant_id) and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (case when p_write then d.can_write else d.can_read or d.can_write end)
 ), denies as (
   select d.* from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
     and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (d.scope_kind='tenant' or (d.scope_kind='site' and d.site_id=p_site_id)
       or (d.scope_kind='org_unit' and d.org_unit_id=p_org_unit_id)
       or (d.scope_kind='assigned_task' and d.task_kind=p_task_kind and d.task_id=p_task_id))
 )
 select coalesce((select c.enabled and exists(select 1 from actor)
   and (c.feature_key is null or private.has_feature_entitlement(p_tenant_id,(select id from actor),c.feature_key))
   and private.people_scope_allowed(p_tenant_id,(select id from actor),p_site_id,p_org_unit_id)
   and (((select member_role='company_superadmin' from actor)
       /* default full access; explicit Deny decisions are applied in the denies CTE */)
     or ((select member_role<>'company_superadmin' from actor) and exists(select 1 from grants g where g.scope_kind='tenant'
       or (g.scope_kind='site' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_sites rs
          where rs.tenant_id=p_tenant_id and rs.membership_role_id=g.assignment_id and rs.site_id=p_site_id
            and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
         or (g.assignment_id is null and g.site_id=p_site_id)))
       or (g.scope_kind='org_unit' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_org_units ro
          where ro.tenant_id=p_tenant_id and ro.membership_role_id=g.assignment_id and ro.org_unit_id=p_org_unit_id
            and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
         or (g.assignment_id is null and g.org_unit_id=p_org_unit_id)))
       or (g.scope_kind='assigned_task' and (g.assignment_id is not null or (g.task_kind=p_task_kind and g.task_id=p_task_id)) and p_task_id is not null and exists(select 1 from iam.task_assignments ta
          where ta.tenant_id=p_tenant_id and ta.membership_id=(select id from actor) and ta.task_kind=p_task_kind
            and ta.task_id=p_task_id and ta.active and (ta.site_id is null or ta.site_id=p_site_id)
            and (ta.org_unit_id is null or ta.org_unit_id=p_org_unit_id))))))
   and not exists(select 1 from denies d where d.protected_origin or not exists(
     select 1 from actor a join iam.member_permission_decisions o on o.tenant_id=p_tenant_id and o.membership_id=a.id
     where o.permission_key=p_permission_key and o.decision='allow' and o.exception_kind='specific_override'
       and o.status='active' and o.starts_at<=now() and (o.ends_at is null or now()<o.ends_at)
       and (case when p_write then o.can_write else o.can_read or o.can_write end)
       and private.decision_source_valid(o.source_delegation_id,o.tenant_id)
       and d.scope_kind='tenant' and o.scope_kind in ('site','org_unit','assigned_task')
       and (o.scope_kind<>'site' or o.site_id=p_site_id)
       and (o.scope_kind<>'org_unit' or o.org_unit_id=p_org_unit_id)
       and (o.scope_kind<>'assigned_task' or (o.task_kind=p_task_kind and o.task_id=p_task_id))

   )) from catalog c),false)
$function$;

CREATE OR REPLACE FUNCTION private.legacy_global_hse_permission_allowed(p_tenant_id uuid, p_permission_key text, p_site_id uuid, p_write boolean, p_task_kind text, p_task_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 with actor as (
   select m.id from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.member_role='employee'
     and m.status='active' and t.status='active' and private.has_member_module_entitlement(p_tenant_id,m.id,'hse')
 ), catalog as (
   select pc.feature_key from iam.permission_catalog pc
   where pc.permission_key=p_permission_key and pc.module_key='hse' and pc.enabled
 ), target as (
   select s.org_unit_id from core.sites s where s.tenant_id=p_tenant_id and s.id=p_site_id
 ), denied as (
   select exists(select 1 from actor a join iam.member_permission_decisions d
      on d.tenant_id=p_tenant_id and d.membership_id=a.id
    where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
      and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
      and (d.scope_kind='tenant'
        or (d.scope_kind='site' and d.site_id=p_site_id)
        or (d.scope_kind='org_unit' and d.org_unit_id=(select org_unit_id from target))
        or (d.scope_kind='assigned_task' and d.task_kind=p_task_kind and d.task_id=p_task_id))) as value
 )
 select coalesce(exists(
   select 1 from actor a cross join catalog c
   where c.feature_key is null or private.has_feature_entitlement(p_tenant_id,a.id,c.feature_key)
 ),false) and coalesce(exists(
   select 1 from actor a cross join catalog c
   join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.tenant_id is null and r.protected
      and r.role_family='employee' and r.active
   join iam.role_permissions rp on rp.role_id=r.id and rp.permission_key=p_permission_key and rp.active
   where mr.role_version_id is null and mr.revoked_at is null and mr.starts_at<=now()
     and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
     and (p_site_id is null or exists(select 1 from iam.site_access sa where sa.tenant_id=p_tenant_id
       and sa.membership_id=a.id and sa.site_id=p_site_id and sa.active))
     and (rp.scope_kind='tenant'
       or (rp.scope_kind='site' and exists(select 1 from iam.membership_role_sites rs
         where rs.tenant_id=p_tenant_id and rs.membership_role_id=mr.id and rs.site_id=p_site_id
           and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
       or (rp.scope_kind='org_unit' and (select org_unit_id from target) is not null
         and exists(select 1 from iam.org_unit_access oa where oa.tenant_id=p_tenant_id
           and oa.membership_id=a.id and oa.org_unit_id=(select org_unit_id from target) and oa.active)
         and exists(select 1 from iam.membership_role_org_units ro where ro.tenant_id=p_tenant_id
           and ro.membership_role_id=mr.id and ro.org_unit_id=(select org_unit_id from target)
           and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
       or (rp.scope_kind='assigned_task' and p_task_id is not null and exists(select 1
         from iam.task_assignments ta where ta.tenant_id=p_tenant_id and ta.membership_id=a.id
           and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active
           and ta.site_id=p_site_id and (ta.org_unit_id is null or ta.org_unit_id=(select org_unit_id from target)))))
     and not (select value from denied)
 ),false)
$function$;

CREATE OR REPLACE FUNCTION api.list_my_entitlements(p_tenant_id uuid)
 RETURNS TABLE(entitlement_kind text, entitlement_key text, entitled boolean)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_membership uuid;
begin
 select m.id into v_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.member_role='company_superadmin'
    and m.status='active' and t.status='active';
 if v_membership is null then raise exception 'active_company_superadmin_required' using errcode='42501'; end if;
 return query select 'module'::text,m.module_key,private.has_member_module_entitlement(p_tenant_id,v_membership,m.module_key) from core.modules m;
 return query select 'feature'::text,f.feature_key,private.has_feature_entitlement(p_tenant_id,v_membership,f.feature_key) from core.features f;
end $function$;

CREATE OR REPLACE FUNCTION api.set_superadmin_capability_limit(p_tenant_id uuid, p_membership_id uuid, p_capability_key text, p_can_use boolean, p_can_delegate boolean, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid();
begin
 if v_actor is null or not private.platform_permission_allowed('superadmin.capability') or p_can_delegate and not p_can_use
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_capability_key not in ('role_assignment','direct_permission_decision','scope_management','permissions.specific_override')
   or not exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=p_membership_id
       and m.member_role='company_superadmin' and m.status='active') then
   raise exception 'superadmin_capability_limit_not_authorized' using errcode='42501';
 end if;
 if exists(select 1 from iam.permission_catalog pc where pc.permission_key=p_capability_key) then
  raise exception 'catalog_permission_restrictions_use_member_decisions' using errcode='22023';
 end if;
 insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
  values(p_tenant_id,p_membership_id,p_capability_key,p_can_use,p_can_delegate,v_actor,btrim(p_reason))
  on conflict(tenant_id,membership_id,capability_key) do update set can_use=excluded.can_use,
   can_delegate=excluded.can_delegate,set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,'tenant','iam.superadmin_capability_limit.set','iam.superadmin_capability_limits',p_membership_id,
    jsonb_build_object('capability_key',p_capability_key,'can_use',p_can_use,'can_delegate',p_can_delegate,'reason',btrim(p_reason)));
end $function$;

CREATE OR REPLACE FUNCTION api.record_feature_usage(p_tenant_id uuid, p_membership_id uuid, p_feature_key text, p_idempotency_key text, p_quantity numeric, p_usage_unit text, p_metadata jsonb DEFAULT '{}'::jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
 v_id uuid; v_existing core.usage_events%rowtype; v_grant core.entitlement_grants%rowtype;
 v_grant_id uuid; v_subscription_id uuid; v_cap numeric; v_used numeric;
 v_rate bigint; v_ccy char(3); v_treatment text:='tenant_billable';
 v_period_start timestamptz; v_period_end timestamptz;
begin
 if auth.role()<>'service_role' or p_tenant_id is null or p_membership_id is null or p_feature_key is null
   or p_quantity is null or p_quantity<=0 or p_idempotency_key is null
   or length(p_idempotency_key) not between 8 and 200 or p_usage_unit is null
   or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb))<>'object'
   or coalesce(p_metadata,'{}'::jsonb) ?| array['prompt','response','completion','token_text','secret','authorization'] then
   raise exception 'trusted_usage_recording_required' using errcode='42501';
 end if;
 -- Lock and replay the key before entitlement/quota checks. Exact retries are
 -- reads of the original immutable event, including after quota exhaustion or
 -- grant expiry. Billing configuration remains the original event snapshot.
 perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-key:'||p_idempotency_key,0));
 select * into v_existing from core.usage_events where idempotency_key=p_idempotency_key for update;
 if found then
   if v_existing.tenant_id is distinct from p_tenant_id
     or v_existing.beneficiary_membership_id is distinct from p_membership_id
     or v_existing.feature_key is distinct from p_feature_key
     or v_existing.usage_unit is distinct from p_usage_unit
     or v_existing.quantity is distinct from p_quantity
     or v_existing.metadata is distinct from coalesce(p_metadata,'{}'::jsonb) then
     raise exception 'idempotency_key_payload_conflict' using errcode='23505';
   end if;
   return v_existing.id;
 end if;

 if not exists(select 1 from core.features f where f.feature_key=p_feature_key and f.usage_unit=p_usage_unit) then
   raise exception 'usage_unit_or_feature_invalid' using errcode='22023';
 end if;

 if not private.has_feature_entitlement(p_tenant_id,p_membership_id,p_feature_key) then
   raise exception 'feature_not_entitled' using errcode='42501';
 end if;

 select * into v_grant from core.entitlement_grants g
  where g.tenant_id=p_tenant_id and g.feature_key=p_feature_key
    and (g.membership_id=p_membership_id or g.membership_id is null)
    and g.can_use and g.status='active' and g.revoked_at is null and g.starts_at<=now() and (g.expires_at is null or now()<g.expires_at)
  order by (g.membership_id is not null) desc,g.starts_at desc,g.id
  limit 1 for share;
 if found then
   v_grant_id:=v_grant.id; v_cap:=v_grant.quota; v_treatment:=v_grant.billing_treatment;
   v_rate:=v_grant.unit_price_minor; v_ccy:=v_grant.currency;
 else
   select s.id,pe.quota,pe.usage_rate_minor,pe.usage_currency,s.current_period_start,s.current_period_end
     into v_subscription_id,v_cap,v_rate,v_ccy,v_period_start,v_period_end
   from core.subscriptions s join core.plans p on p.id=s.plan_id and p.status='active'
     join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
   where s.tenant_id=p_tenant_id and pe.feature_key=p_feature_key and s.status in ('active','trialing')
     and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
     and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at)
   limit 1 for share of s,si;
   if v_subscription_id is null then raise exception 'feature_not_entitled' using errcode='42501'; end if;
 end if;

 if v_cap is not null then
   if v_grant_id is not null then
     perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-quota-grant:'||v_grant_id::text,0));
     select coalesce(sum(quantity),0) into v_used from core.usage_events where grant_id=v_grant_id;
   else
     perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-quota-sub:'||p_tenant_id::text||':'||p_feature_key||':'||v_period_start::text,0));
     select coalesce(sum(quantity),0) into v_used from core.usage_events
       where tenant_id=p_tenant_id and feature_key=p_feature_key and grant_id is null
         and occurred_at>=v_period_start and occurred_at<v_period_end;
   end if;
   if v_used+p_quantity>v_cap then raise exception 'grant_usage_quota_exceeded' using errcode='54000'; end if;
 end if;

 insert into core.usage_events(tenant_id,beneficiary_membership_id,feature_key,grant_id,payer_tenant_id,
   billing_treatment,idempotency_key,usage_unit,quantity,unit_price_minor,currency,metadata)
 values(p_tenant_id,p_membership_id,p_feature_key,v_grant_id,
   case when v_treatment='tenant_billable' then p_tenant_id end,v_treatment,p_idempotency_key,p_usage_unit,
   p_quantity,v_rate,v_ccy,coalesce(p_metadata,'{}'::jsonb))
 on conflict do nothing returning id into v_id;
 if v_id is null then
   select * into v_existing from core.usage_events where idempotency_key=p_idempotency_key;
   if v_existing.tenant_id is distinct from p_tenant_id
     or v_existing.beneficiary_membership_id is distinct from p_membership_id
     or v_existing.feature_key is distinct from p_feature_key
     or v_existing.usage_unit is distinct from p_usage_unit
     or v_existing.quantity is distinct from p_quantity
     or v_existing.metadata is distinct from coalesce(p_metadata,'{}'::jsonb) then
     raise exception 'idempotency_key_payload_conflict' using errcode='23505';
   end if;
   return v_existing.id;
 end if;
 return v_id;
end $function$;

CREATE OR REPLACE FUNCTION private.apply_invitation_phase1_defaults()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_membership uuid;v_family text;v_default record;
begin
 if new.accepted_at is null or old.accepted_at is not null then return new;end if;
 select m.id into v_membership from iam.memberships m where m.tenant_id=new.tenant_id
  and m.user_id=new.accepted_by and m.status='active' and m.member_role=new.intended_level;
 if v_membership is null then raise exception 'accepted_membership_missing' using errcode='23514';end if;
 if new.intended_level='company_superadmin' then
  insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
  select new.tenant_id,v_membership,l.permission_key,l.can_use,l.can_delegate,l.set_by,l.reason
   from iam.superadmin_invitation_limits l where l.tenant_id=new.tenant_id and l.invitation_id=new.id
  on conflict(tenant_id,membership_id,capability_key) do update set can_use=excluded.can_use,can_delegate=excluded.can_delegate,set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
  -- Restrictions on catalog permissions become explicit Direct Deny decisions (the
  -- evaluator no longer reads capability limits for catalog keys).
  perform set_config('sentriq.invitation_restriction_deny','on',true);
  insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,status,granted_by,reason)
  select new.tenant_id,v_membership,l.permission_key,'deny','tenant',false,false,'active',l.set_by,
   left('Superadmin invitation restriction: '||coalesce(l.reason,'no reason recorded'),500)
   from iam.superadmin_invitation_limits l join iam.permission_catalog pc on pc.permission_key=l.permission_key and pc.enabled
   where l.tenant_id=new.tenant_id and l.invitation_id=new.id and not l.can_use
    and not exists(select 1 from iam.member_permission_decisions d where d.tenant_id=new.tenant_id and d.membership_id=v_membership
      and d.permission_key=l.permission_key and d.decision='deny' and d.scope_kind='tenant' and d.status='active');
  perform set_config('sentriq.invitation_restriction_deny','off',true);
  update iam.superadmin_invitation_limits set invitation_id=null,membership_id=v_membership where tenant_id=new.tenant_id and invitation_id=new.id;
  return new;
 end if;
 v_family:=case when new.intended_level='employee' then 'employee' else 'admin' end;
 select d.profile_id,d.profile_version_id,d.source_delegation_id into v_default from iam.permission_profile_defaults d
 join iam.permission_profiles p on p.tenant_id=d.tenant_id and p.id=d.profile_id and p.active and p.role_family=d.role_family
 join iam.permission_profile_versions v on v.tenant_id=d.tenant_id and v.id=d.profile_version_id and v.profile_id=p.id
 where d.tenant_id=new.tenant_id and d.role_family=v_family
  and private.decision_source_valid(d.source_delegation_id,d.tenant_id);
 if v_default.profile_id is not null then
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and membership_id=v_membership and is_current;
  insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,source,assigned_by,is_current,source_delegation_id)
  values(new.tenant_id,v_membership,v_family,v_default.profile_id,v_default.profile_version_id,'invitation_default',new.invited_by,true,v_default.source_delegation_id);
 end if;
 return new;
end $function$;

-- ---------------------------------------------------------------------------
-- Superadmin capability limits -> explicit Direct Deny decisions
-- ---------------------------------------------------------------------------
-- Each existing limit is interpreted individually. Only a can_use=false limit on
-- an enabled catalog permission becomes a tenant-scope Deny decision (tenant,
-- member, date, setter and reason preserved). Nothing else is converted. Rows that
-- cannot be interpreted reliably are recorded for review and left untouched.
create table iam.superadmin_limit_migration_review(
 tenant_id uuid not null, membership_id uuid not null, capability_key text not null,
 source_can_use boolean not null, source_can_delegate boolean not null, source_set_by uuid,
 source_reason text, source_updated_at timestamptz,
 outcome text not null check (outcome in ('converted_to_deny','not_a_restriction','needs_review')),
 note text not null, decision_id uuid, migrated_at timestamptz not null default now(),
 primary key(tenant_id,membership_id,capability_key));
alter table iam.superadmin_limit_migration_review enable row level security;
alter table iam.superadmin_limit_migration_review force row level security;
revoke all on iam.superadmin_limit_migration_review from public,anon,authenticated,service_role;
grant select on iam.superadmin_limit_migration_review to authenticated;
create policy limit_migration_review_operator_read on iam.superadmin_limit_migration_review
  for select to authenticated using (private.is_platform_operator());

do $mig$
declare l record; v_dec uuid; v_in_catalog boolean; v_member boolean;
begin
 for l in select * from iam.superadmin_capability_limits order by updated_at,tenant_id,membership_id,capability_key loop
  v_in_catalog:=exists(select 1 from iam.permission_catalog where permission_key=l.capability_key and enabled);
  v_member:=exists(select 1 from iam.memberships where tenant_id=l.tenant_id and id=l.membership_id);
  v_dec:=null;
  if l.can_use and l.can_delegate then
   insert into iam.superadmin_limit_migration_review values(l.tenant_id,l.membership_id,l.capability_key,l.can_use,l.can_delegate,
     l.set_by,l.reason,l.updated_at,'not_a_restriction','Full use and delegation: Default access, nothing to convert.',null);
  elsif l.can_use then
   insert into iam.superadmin_limit_migration_review values(l.tenant_id,l.membership_id,l.capability_key,l.can_use,l.can_delegate,
     l.set_by,l.reason,l.updated_at,'needs_review','Use allowed, delegation withheld. Delegation now lives on the individual entitlement (can_delegate); not converted to Deny.',null);
  elsif v_in_catalog and v_member and l.set_by is not null then
   select d.id into v_dec from iam.member_permission_decisions d where d.tenant_id=l.tenant_id and d.membership_id=l.membership_id
     and d.permission_key=l.capability_key and d.decision='deny' and d.scope_kind='tenant' and d.status='active';
   if v_dec is null then
    insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,
      status,granted_by,starts_at,reason,protected_origin)
    values(l.tenant_id,l.membership_id,l.capability_key,'deny','tenant',false,false,'active',l.set_by,
      least(l.updated_at,now()),left('Migrated from superadmin capability limit: '||coalesce(l.reason,'no reason recorded'),500),true)
    returning id into v_dec;
   end if;
   insert into iam.superadmin_limit_migration_review values(l.tenant_id,l.membership_id,l.capability_key,l.can_use,l.can_delegate,
     l.set_by,l.reason,l.updated_at,'converted_to_deny','Converted to a tenant-scope Direct Deny decision.',v_dec);
  else
   insert into iam.superadmin_limit_migration_review values(l.tenant_id,l.membership_id,l.capability_key,l.can_use,l.can_delegate,
     l.set_by,l.reason,l.updated_at,'needs_review',
     case when not v_in_catalog then 'Key is not an enabled catalog permission (management capability or retired key). Left in place for review.'
          when not v_member then 'Membership no longer exists. Left for review.' else 'Missing setter. Left for review.' end,null);
  end if;
 end loop;
end $mig$;

-- ---------------------------------------------------------------------------
-- Privileges
-- ---------------------------------------------------------------------------
revoke all on function api.platform_set_member_decision(uuid,uuid,text,text,text,text,uuid,uuid,timestamptz,boolean,boolean),
 api.platform_set_member_entitlement(uuid,uuid,text,text,text,boolean,boolean,timestamptz,timestamptz),
 api.platform_revoke_member_entitlement(uuid,text),
 api.delegate_member_entitlement(uuid,uuid,uuid,text,timestamptz),
 api.revoke_delegated_entitlement(uuid,text),
 api.member_effective_access(uuid,uuid) from public,anon,service_role;
grant execute on function api.platform_set_member_decision(uuid,uuid,text,text,text,text,uuid,uuid,timestamptz,boolean,boolean),
 api.platform_set_member_entitlement(uuid,uuid,text,text,text,boolean,boolean,timestamptz,timestamptz),
 api.platform_revoke_member_entitlement(uuid,text),
 api.delegate_member_entitlement(uuid,uuid,uuid,text,timestamptz),
 api.revoke_delegated_entitlement(uuid,text),
 api.member_effective_access(uuid,uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Review hardening
-- ---------------------------------------------------------------------------
-- Must be applied as the postgres role (migration runner): the decision triggers
-- let session_user=postgres bypass their guards, and the data migration above
-- writes protected rows directly.

-- Legacy platform grant RPCs: membership-scoped rows are Operation A/B territory.
-- They require member.entitlements, refuse self-targets, and a personal
-- restriction can never be lifted by suspending it (revoke it with the audited RPC).
create or replace function api.issue_entitlement_grant(p_tenant_id uuid, p_module_key text, p_feature_key text, p_membership_id uuid, p_starts_at timestamptz, p_expires_at timestamptz, p_reason text, p_billing_treatment text, p_currency character, p_unit_price_minor bigint, p_quota numeric default null)
 returns uuid language plpgsql security definer set search_path to '' as $function$
declare v_id uuid;
begin
 if not private.platform_permission_allowed('entitlement.issue') or p_starts_at is null or p_expires_at is null or p_starts_at>=p_expires_at
   or ((p_module_key is not null)::integer+(p_feature_key is not null)::integer<>1)
   or (p_module_key is not null and p_membership_id is not null)
   or p_billing_treatment not in ('tenant_billable','complimentary','platform_absorbed')
   or (p_unit_price_minor is not null and p_currency is null)
   or (p_currency is not null and p_currency::text !~ '^[A-Z]{3}$') then
   if p_module_key is not null and p_membership_id is not null then
     raise exception 'module_grants_are_tenant_scoped' using errcode='22023';
   end if;
   raise exception 'grant_not_allowed' using errcode='42501';
 end if;
 if p_membership_id is not null and (not private.platform_permission_allowed('member.entitlements')
    or exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=p_membership_id and m.user_id=auth.uid())) then
   raise exception 'grant_not_allowed' using errcode='42501';
 end if;
 if p_membership_id is not null and not exists(select 1 from iam.memberships
    where tenant_id=p_tenant_id and id=p_membership_id) then
   raise exception 'grant_membership_mismatch' using errcode='23503';
 end if;
 if p_module_key is not null and not exists(select 1 from core.modules where module_key=p_module_key) then
   raise exception 'module_disabled_or_unknown' using errcode='22023';
 end if;
 if p_feature_key is not null and not exists(select 1 from core.features where feature_key=p_feature_key and enabled) then
   raise exception 'feature_disabled_or_unknown' using errcode='22023';
 end if;
 insert into core.entitlement_grants(tenant_id,module_key,feature_key,membership_id,starts_at,expires_at,
   granted_by,reason,billing_treatment,bill_to_tenant_id,currency,unit_price_minor,quota)
 values(p_tenant_id,p_module_key,p_feature_key,p_membership_id,p_starts_at,p_expires_at,auth.uid(),p_reason,
   p_billing_treatment,case when p_billing_treatment='tenant_billable' then p_tenant_id end,
   p_currency,p_unit_price_minor,p_quota) returning id into v_id;
 return v_id;
end $function$;

create or replace function api.set_entitlement_grant_status(p_grant_id uuid, p_status text, p_reason text)
 returns void language plpgsql security definer set search_path to '' as $function$
declare v_tenant uuid; v_old_status text; v_mem uuid; v_use boolean;
begin
 if not private.platform_permission_allowed('entitlement.status') or p_status not in ('active','suspended')
   or length(btrim(coalesce(p_reason,'')))<3 then
   raise exception 'grant_status_update_not_allowed' using errcode='42501';
 end if;
 select tenant_id,status,membership_id,can_use into v_tenant,v_old_status,v_mem,v_use from core.entitlement_grants
   where id=p_grant_id and revoked_at is null for update;
 if not found then raise exception 'grant_not_found_or_revoked' using errcode='22023'; end if;
 if v_mem is not null and (not private.platform_permission_allowed('member.entitlements')
    or exists(select 1 from iam.memberships m where m.tenant_id=v_tenant and m.id=v_mem and m.user_id=auth.uid())) then
   raise exception 'grant_status_update_not_allowed' using errcode='42501';
 end if;
 if not v_use and p_status<>'active' then
   raise exception 'restriction_cannot_be_suspended' using errcode='42501';
 end if;
 if v_old_status=p_status then return; end if;
 update core.entitlement_grants set status=p_status where id=p_grant_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(null,auth.uid(),'platform','core.entitlement_grants.status_changed','core.entitlement_grants',p_grant_id,
   jsonb_build_object('tenant_id',v_tenant,'before_status',v_old_status,'after_status',p_status,'reason',p_reason));
end $function$;

create or replace function api.revoke_entitlement_grant(p_grant_id uuid, p_reason text)
 returns void language plpgsql security definer set search_path to '' as $function$
declare v_tenant uuid; v_mem uuid;
begin
 if not private.platform_permission_allowed('entitlement.revoke') or length(btrim(coalesce(p_reason,'')))<3 then raise exception 'grant_revocation_not_allowed' using errcode='42501'; end if;
 select tenant_id,membership_id into v_tenant,v_mem from core.entitlement_grants where id=p_grant_id and revoked_at is null;
 if v_mem is not null and (not private.platform_permission_allowed('member.entitlements')
    or exists(select 1 from iam.memberships m where m.tenant_id=v_tenant and m.id=v_mem and m.user_id=auth.uid())) then
   raise exception 'grant_revocation_not_allowed' using errcode='42501';
 end if;
 update core.entitlement_grants set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=p_reason where id=p_grant_id and revoked_at is null;
 if not found then raise exception 'grant_not_active' using errcode='22023'; end if;
end $function$;

-- Usage is attributed only to a live grant (parent holder, expiry and restrictions included).
CREATE OR REPLACE FUNCTION api.record_feature_usage(p_tenant_id uuid, p_membership_id uuid, p_feature_key text, p_idempotency_key text, p_quantity numeric, p_usage_unit text, p_metadata jsonb DEFAULT '{}'::jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
 v_id uuid; v_existing core.usage_events%rowtype; v_grant core.entitlement_grants%rowtype;
 v_grant_id uuid; v_subscription_id uuid; v_cap numeric; v_used numeric;
 v_rate bigint; v_ccy char(3); v_treatment text:='tenant_billable';
 v_period_start timestamptz; v_period_end timestamptz;
begin
 if auth.role()<>'service_role' or p_tenant_id is null or p_membership_id is null or p_feature_key is null
   or p_quantity is null or p_quantity<=0 or p_idempotency_key is null
   or length(p_idempotency_key) not between 8 and 200 or p_usage_unit is null
   or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb))<>'object'
   or coalesce(p_metadata,'{}'::jsonb) ?| array['prompt','response','completion','token_text','secret','authorization'] then
   raise exception 'trusted_usage_recording_required' using errcode='42501';
 end if;
 -- Lock and replay the key before entitlement/quota checks. Exact retries are
 -- reads of the original immutable event, including after quota exhaustion or
 -- grant expiry. Billing configuration remains the original event snapshot.
 perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-key:'||p_idempotency_key,0));
 select * into v_existing from core.usage_events where idempotency_key=p_idempotency_key for update;
 if found then
   if v_existing.tenant_id is distinct from p_tenant_id
     or v_existing.beneficiary_membership_id is distinct from p_membership_id
     or v_existing.feature_key is distinct from p_feature_key
     or v_existing.usage_unit is distinct from p_usage_unit
     or v_existing.quantity is distinct from p_quantity
     or v_existing.metadata is distinct from coalesce(p_metadata,'{}'::jsonb) then
     raise exception 'idempotency_key_payload_conflict' using errcode='23505';
   end if;
   return v_existing.id;
 end if;

 if not exists(select 1 from core.features f where f.feature_key=p_feature_key and f.usage_unit=p_usage_unit) then
   raise exception 'usage_unit_or_feature_invalid' using errcode='22023';
 end if;

 if not private.has_feature_entitlement(p_tenant_id,p_membership_id,p_feature_key) then
   raise exception 'feature_not_entitled' using errcode='42501';
 end if;

 select * into v_grant from core.entitlement_grants g
  where g.tenant_id=p_tenant_id and g.feature_key=p_feature_key
    and (g.membership_id=p_membership_id or g.membership_id is null)
    and g.can_use and private.entitlement_grant_live(g.id)
  order by (g.membership_id is not null) desc,g.starts_at desc,g.id
  limit 1 for share;
 if found then
   v_grant_id:=v_grant.id; v_cap:=v_grant.quota; v_treatment:=v_grant.billing_treatment;
   v_rate:=v_grant.unit_price_minor; v_ccy:=v_grant.currency;
 else
   select s.id,pe.quota,pe.usage_rate_minor,pe.usage_currency,s.current_period_start,s.current_period_end
     into v_subscription_id,v_cap,v_rate,v_ccy,v_period_start,v_period_end
   from core.subscriptions s join core.plans p on p.id=s.plan_id and p.status='active'
     join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
   where s.tenant_id=p_tenant_id and pe.feature_key=p_feature_key and s.status in ('active','trialing')
     and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
     and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at)
   limit 1 for share of s,si;
   if v_subscription_id is null then raise exception 'feature_not_entitled' using errcode='42501'; end if;
 end if;

 if v_cap is not null then
   if v_grant_id is not null then
     perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-quota-grant:'||v_grant_id::text,0));
     select coalesce(sum(quantity),0) into v_used from core.usage_events where grant_id=v_grant_id;
   else
     perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-quota-sub:'||p_tenant_id::text||':'||p_feature_key||':'||v_period_start::text,0));
     select coalesce(sum(quantity),0) into v_used from core.usage_events
       where tenant_id=p_tenant_id and feature_key=p_feature_key and grant_id is null
         and occurred_at>=v_period_start and occurred_at<v_period_end;
   end if;
   if v_used+p_quantity>v_cap then raise exception 'grant_usage_quota_exceeded' using errcode='54000'; end if;
 end if;

 insert into core.usage_events(tenant_id,beneficiary_membership_id,feature_key,grant_id,payer_tenant_id,
   billing_treatment,idempotency_key,usage_unit,quantity,unit_price_minor,currency,metadata)
 values(p_tenant_id,p_membership_id,p_feature_key,v_grant_id,
   case when v_treatment='tenant_billable' then p_tenant_id end,v_treatment,p_idempotency_key,p_usage_unit,
   p_quantity,v_rate,v_ccy,coalesce(p_metadata,'{}'::jsonb))
 on conflict do nothing returning id into v_id;
 if v_id is null then
   select * into v_existing from core.usage_events where idempotency_key=p_idempotency_key;
   if v_existing.tenant_id is distinct from p_tenant_id
     or v_existing.beneficiary_membership_id is distinct from p_membership_id
     or v_existing.feature_key is distinct from p_feature_key
     or v_existing.usage_unit is distinct from p_usage_unit
     or v_existing.quantity is distinct from p_quantity
     or v_existing.metadata is distinct from coalesce(p_metadata,'{}'::jsonb) then
     raise exception 'idempotency_key_payload_conflict' using errcode='23505';
   end if;
   return v_existing.id;
 end if;
 return v_id;
end $function$;

-- Invitations and delegations: the module check is member-aware (invitation flow itself stays out of scope).
CREATE OR REPLACE FUNCTION api.create_company_invitation(p_tenant_id uuid, p_email text, p_level text, p_ttl interval DEFAULT '7 days'::interval)
 RETURNS TABLE(invitation_id uuid, token text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_token text:=encode(extensions.gen_random_bytes(32),'hex');
        v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if v_actor is null or p_level not in ('company_admin','employee') or v_email is null
   or length(v_email)<3 or length(v_email)>254 or p_ttl is null
   or p_ttl<=interval '0' or p_ttl>interval '30 days'
   or not exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
      where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.member_role='company_superadmin'
        and m.status='active' and t.status='active' and private.has_member_module_entitlement(p_tenant_id,m.id,'hse')) then
   raise exception 'company_invitation_not_allowed' using errcode='42501';
 end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-invitation:'||p_tenant_id::text||':'||v_email,0));
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.email=v_email and m.status='active') then
   raise exception 'active_membership_already_exists' using errcode='23505';
 end if;
 update iam.invitations set revoked_at=now(),revoked_by=v_actor,revoke_reason='Expired before reinvitation'
  where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null and expires_at<=now();
 if exists(select 1 from iam.invitations where tenant_id=p_tenant_id and email=v_email
    and accepted_at is null and revoked_at is null) then
   raise exception 'invitation_already_pending' using errcode='23505';
 end if;
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),p_level,v_actor,now()+p_ttl)
 returning id into v_id;
 return query select v_id,v_token;
end $function$;

CREATE OR REPLACE FUNCTION api.create_delegation(p_tenant_id uuid, p_delegate_membership_id uuid, p_level text, p_site_id uuid, p_org_unit_id uuid, p_allowed_capabilities text[], p_starts_at timestamp with time zone, p_ends_at timestamp with time zone, p_reason text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_grantor uuid; v_parent uuid; v_id uuid; c text;
begin
 select m.id into v_grantor from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active'
    and private.has_member_module_entitlement(p_tenant_id,m.id,'hse');
 if v_actor is null or v_grantor is null or p_allowed_capabilities is null or cardinality(p_allowed_capabilities)=0
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_starts_at is null or (p_ends_at is not null and p_ends_at<=p_starts_at) then
   raise exception 'delegation_request_invalid' using errcode='22023';
 end if;
 foreach c in array p_allowed_capabilities loop
   if not private.phase1_can_manage(p_tenant_id,c,p_delegate_membership_id,p_site_id,p_org_unit_id) then
     raise exception 'delegation_capability_not_authorized' using errcode='42501';
   end if;
 end loop;
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=v_grantor and m.member_role<>'company_superadmin') then
   select d.id into v_parent from iam.delegation_envelopes d where d.tenant_id=p_tenant_id
    and d.delegate_membership_id=v_grantor and d.status='active' and d.starts_at<=now()
    and (d.ends_at is null or now()<d.ends_at)
    and p_allowed_capabilities <@ d.allowed_capabilities
    and ((d.level='tenant') or (d.level='employees_default' and p_level='employees_default')
      or (d.level='site' and p_level='site' and d.site_id=p_site_id)
      or (d.level='org_unit' and p_level='org_unit' and d.org_unit_id=p_org_unit_id))
    and (d.ends_at is null or (p_ends_at is not null and p_ends_at<=d.ends_at))
    order by d.created_at desc limit 1;
   if v_parent is null then raise exception 'delegation_parent_envelope_required' using errcode='42501'; end if;
 end if;
 insert into iam.delegation_envelopes(tenant_id,grantor_membership_id,delegate_membership_id,level,site_id,org_unit_id,
   allowed_capabilities,starts_at,ends_at,parent_envelope_id,created_by)
 values(p_tenant_id,v_grantor,p_delegate_membership_id,p_level,p_site_id,p_org_unit_id,p_allowed_capabilities,
   p_starts_at,p_ends_at,v_parent,v_actor) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_grantor,p_level,'iam.delegation.created','iam.delegation_envelopes',v_id,
   jsonb_build_object('delegate_membership_id',p_delegate_membership_id,'capabilities',p_allowed_capabilities,'reason',btrim(p_reason)));
 return v_id;
end $function$;

-- people_scope_allowed is an internal helper; callers are definer functions only.
revoke all on function private.people_scope_allowed(uuid,uuid,uuid,uuid) from public,anon,authenticated;

-- member_effective_access reports the tenant-wide result. Site and org-unit people
-- scope (private.people_scope_allowed) only narrows a request that names a site or
-- org unit, so it cannot change a tenant-wide answer; scoped rows are flagged
-- scoped=true and must be evaluated by api.authorize with the concrete scope.
comment on function api.member_effective_access(uuid,uuid) is
 'Tenant-wide effective access. Scoped results (scoped=true) are not tenant-wide; use api.authorize with the concrete site or org unit.';
