-- Platform Owner controls the Sub-owner permission set. No functional role can grant it.
begin;
create table iam.platform_permission_catalog(permission_key text primary key);
insert into iam.platform_permission_catalog(permission_key) values
('company.lifecycle'),
('module.toggle'),
('feature.toggle'),
('plan.publish'),
('subscription.create'),
('subscription.update'),
('entitlement.issue'),
('entitlement.revoke'),
('entitlement.status'),
('company.create'),
('delegation.review'),
('delegation.revoke'),
('membership.lifecycle'),
('superadmin.invite'),
('superadmin.capability');
create table iam.platform_permission_grants(
 user_id uuid not null references iam.platform_operators(user_id),
 permission_key text not null references iam.platform_permission_catalog(permission_key),
 granted boolean not null,updated_by uuid not null references auth.users(id),
 reason text not null check(length(btrim(reason)) between 3 and 500),updated_at timestamptz not null default now(),
 primary key(user_id,permission_key));
alter table iam.platform_permission_catalog enable row level security;
alter table iam.platform_permission_catalog force row level security;
alter table iam.platform_permission_grants enable row level security;
alter table iam.platform_permission_grants force row level security;
revoke all on iam.platform_permission_catalog,iam.platform_permission_grants from public,anon,authenticated,service_role;
create or replace function private.platform_permission_allowed(p_key text,p_actor uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.platform_operators o where o.user_id=coalesce(p_actor,private.request_actor_id()) and o.active
  and (o.operator_role='owner' or exists(select 1 from iam.platform_permission_grants g
   where g.user_id=o.user_id and g.permission_key=p_key and g.granted)))
$$;
create or replace function api.set_subowner_platform_permission(p_user_id uuid,p_permission_key text,p_granted boolean,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_owner() then raise exception 'only_owner_can_manage_platform_permissions' using errcode='42501';end if;
 if p_granted is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or not exists(select 1 from iam.platform_operators where user_id=p_user_id and operator_role='subowner' and active)
  or not exists(select 1 from iam.platform_permission_catalog where permission_key=p_permission_key) then
  raise exception 'platform_permission_request_invalid' using errcode='22023';end if;
 insert into iam.platform_permission_grants(user_id,permission_key,granted,updated_by,reason)
 values(p_user_id,p_permission_key,p_granted,private.request_actor_id(),btrim(p_reason))
 on conflict(user_id,permission_key) do update set granted=excluded.granted,updated_by=excluded.updated_by,reason=excluded.reason,updated_at=now();
 insert into audit.events(actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(private.request_actor_id(),'platform','platform.subowner_permission.set','iam.platform_permission_grants',p_user_id,
  jsonb_build_object('permission_key',p_permission_key,'granted',p_granted,'reason',btrim(p_reason)));
end $$;
create or replace function private.initialize_subowner_permissions() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.operator_role='subowner' then
  insert into iam.platform_permission_grants(user_id,permission_key,granted,updated_by,reason)
   values(new.user_id,'company.lifecycle',true,coalesce(new.created_by,new.user_id),'Confirmed Subowner lifecycle default');
  insert into audit.events(actor_user_id,scope_kind,action_key,record_type,record_id,summary)
   values(coalesce(new.created_by,new.user_id),'platform','platform.subowner_permission.default','iam.platform_permission_grants',new.user_id,
    jsonb_build_object('permission_key','company.lifecycle','granted',true));
 end if;
 return new;
end $$;
create trigger subowner_default_permissions after insert on iam.platform_operators for each row execute function private.initialize_subowner_permissions();
-- Existing Subowners receive only the confirmed default. All other writes fail closed.
insert into iam.platform_permission_grants(user_id,permission_key,granted,updated_by,reason)
 select o.user_id,'company.lifecycle',true,coalesce(o.created_by,o.user_id),'Confirmed Subowner lifecycle default'
 from iam.platform_operators o where o.operator_role='subowner';
revoke all on function private.platform_permission_allowed(text,uuid),private.initialize_subowner_permissions() from public,anon,authenticated,service_role;
revoke all on function api.set_subowner_platform_permission(uuid,text,boolean,text) from public,anon,service_role;
grant execute on function api.set_subowner_platform_permission(uuid,text,boolean,text) to authenticated;
-- All platform writes use RPCs. No direct table path may bypass grant checks or audit.
drop policy if exists tenant_update on core.tenants;
drop policy if exists grants_insert on core.entitlement_grants;
drop policy if exists grants_update on core.entitlement_grants;
drop policy if exists tenant_domains_insert on core.tenant_domains;
drop policy if exists tenant_domains_update on core.tenant_domains;
CREATE OR REPLACE FUNCTION api.create_company_superadmin_invitation(p_tenant_id uuid, p_email text, p_ttl interval, p_limits jsonb, p_reason text)
 RETURNS TABLE(invitation_id uuid, token text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_token text:=encode(extensions.gen_random_bytes(32),'hex');
        v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if v_actor is null or not private.platform_permission_allowed('superadmin.invite') or v_email is null
   or length(v_email)<3 or length(v_email)>254 or p_ttl is null or p_ttl<=interval '0'
   or p_ttl>interval '30 days' or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or not exists(select 1 from core.tenants t where t.id=p_tenant_id and t.status='active')
   or jsonb_typeof(p_limits)<>'array' or jsonb_array_length(p_limits)>100 then
   raise exception 'company_superadmin_invitation_not_allowed' using errcode='42501';
 end if;
 if exists(select 1 from jsonb_array_elements(p_limits) as e(value)
   where jsonb_typeof(e.value)<>'object' or exists(select 1 from jsonb_object_keys(e.value) as k(key)
     where k.key not in ('permission_key','can_use','can_delegate','reason')))
   or exists(select 1 from jsonb_to_recordset(p_limits) as x(
       permission_key text,can_use boolean,can_delegate boolean,reason text)
     where permission_key is null or can_use is null or can_delegate is null
       or can_delegate and not can_use or reason is null or length(btrim(reason)) not between 3 and 500
       or not (permission_key in ('role_assignment','direct_permission_decision','scope_management','permissions.specific_override')
          or exists(select 1 from iam.permission_catalog pc where pc.permission_key=x.permission_key and pc.module_key='hse')))
   then raise exception 'superadmin_invitation_limit_invalid' using errcode='22023'; end if;
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
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),'company_superadmin',v_actor,now()+p_ttl)
 returning id into v_id;
 insert into iam.superadmin_invitation_limits(tenant_id,invitation_id,permission_key,can_use,can_delegate,set_by,reason)
  select p_tenant_id,v_id,x.permission_key,x.can_use,x.can_delegate,v_actor,btrim(x.reason)
   from jsonb_to_recordset(p_limits) as x(permission_key text,can_use boolean,can_delegate boolean,reason text);
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,'tenant','iam.superadmin.invitation.created','iam.invitations',v_id,
    jsonb_build_object('email',v_email,'limit_count',jsonb_array_length(p_limits),'reason',btrim(p_reason)));
 return query select v_id,v_token;
end $function$
;
CREATE OR REPLACE FUNCTION api.create_subscription(p_tenant_id uuid, p_plan_id uuid, p_starts_at timestamp with time zone, p_period_end timestamp with time zone, p_currency character, p_items jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_sub uuid; v_item jsonb;
begin
 if not private.platform_permission_allowed('subscription.create') or p_tenant_id is null or p_plan_id is null
   or p_starts_at is null or p_period_end is null or p_starts_at>=p_period_end
   or p_currency is null or jsonb_typeof(p_items)<>'array' or jsonb_array_length(p_items)=0 then
   raise exception 'subscription_not_allowed' using errcode='42501';
 end if;
 if not exists(select 1 from core.plans p where p.id=p_plan_id and p.status='active' and p.currency=p_currency) then
   raise exception 'plan_unavailable_or_currency_mismatch' using errcode='22023';
 end if;
 insert into core.subscriptions(tenant_id,plan_id,status,starts_at,current_period_start,current_period_end,created_by)
 values(p_tenant_id,p_plan_id,'active',p_starts_at,p_starts_at,p_period_end,auth.uid()) returning id into v_sub;
 for v_item in select value from jsonb_array_elements(p_items) loop
   if not exists(select 1 from core.plan_entitlements pe where pe.id=(v_item->>'plan_entitlement_id')::uuid and pe.plan_id=p_plan_id) then
     raise exception 'subscription_item_not_in_plan' using errcode='22023';
   end if;
   insert into core.subscription_items(tenant_id,subscription_id,plan_entitlement_id,quantity,
     unit_price_minor,currency,starts_at,ends_at)
   values(p_tenant_id,v_sub,(v_item->>'plan_entitlement_id')::uuid,
     coalesce((v_item->>'quantity')::numeric,1),(v_item->>'unit_price_minor')::bigint,
     p_currency,p_starts_at,p_period_end);
 end loop;
 if (select count(*) from core.subscription_items where subscription_id=v_sub)<>
    (select count(*) from core.plan_entitlements where plan_id=p_plan_id) then
   raise exception 'subscription_requires_all_plan_entitlements' using errcode='22023';
 end if;
 return v_sub;
end $function$
;
CREATE OR REPLACE FUNCTION api.create_tenant(p_name text, p_industry_label text, p_company_superadmin uuid)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_id uuid;
begin
 if not private.platform_permission_allowed('company.create') then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 if not exists(select 1 from auth.users u where u.id=p_company_superadmin)
   or exists(select 1 from iam.platform_operators p where p.user_id=p_company_superadmin) then raise exception 'company_superadmin_user_missing_or_is_operator' using errcode='22023'; end if;
 insert into core.tenants(name,industry_label,created_by) values(btrim(p_name),nullif(btrim(p_industry_label),''),auth.uid()) returning id into v_id;
 insert into iam.memberships(tenant_id,user_id,member_role,status) values(v_id,p_company_superadmin,'company_superadmin','active');
 return v_id;
end $function$
;
CREATE OR REPLACE FUNCTION api.issue_entitlement_grant(p_tenant_id uuid, p_module_key text, p_feature_key text, p_membership_id uuid, p_starts_at timestamp with time zone, p_expires_at timestamp with time zone, p_reason text, p_billing_treatment text, p_currency character, p_unit_price_minor bigint, p_quota numeric DEFAULT NULL::numeric)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
end $function$
;
CREATE OR REPLACE FUNCTION api.platform_set_membership_status(p_tenant_id uuid, p_membership_id uuid, p_status text, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if not private.is_platform_owner() and exists(select 1 from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and member_role='company_superadmin') then
  raise exception 'superadmin_lifecycle_owner_only' using errcode='42501';end if;
 if not private.platform_permission_allowed('membership.lifecycle') or p_status not in ('active','suspended','ended')
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_membership_lifecycle_not_authorized' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-membership:'||p_tenant_id::text,0));
 update iam.memberships set status=p_status where tenant_id=p_tenant_id and id=p_membership_id;
 if not found then raise exception 'membership_not_found' using errcode='22023'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.platform.membership_status','iam.memberships',p_membership_id,
  jsonb_build_object('status',p_status,'reason',btrim(p_reason)));
end $function$
;
CREATE OR REPLACE FUNCTION api.publish_plan(p_plan_key text, p_version integer, p_name text, p_currency character, p_price_minor bigint, p_entitlements jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_plan uuid; v_item jsonb; v_module text; v_feature text;
begin
 if not private.platform_permission_allowed('plan.publish') or p_version<1 or p_price_minor<0 or jsonb_typeof(p_entitlements)<>'array' or jsonb_array_length(p_entitlements)=0 then
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
end $function$
;
CREATE OR REPLACE FUNCTION api.review_delegation(p_tenant_id uuid, p_envelope_id uuid, p_action text, p_new_ends_at timestamp with time zone, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_d iam.delegation_envelopes%rowtype; v_old_end timestamptz;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_action not in ('extend','confirm_expired') then raise exception 'delegation_review_invalid' using errcode='22023'; end if;
 select * into v_d from iam.delegation_envelopes where tenant_id=p_tenant_id and id=p_envelope_id for update;
 if not found or (v_d.created_by<>v_actor and not private.platform_permission_allowed('delegation.review'))
   or v_d.status<>'active' then raise exception 'delegation_review_not_authorized' using errcode='42501'; end if;
 v_old_end:=v_d.ends_at;
 if p_action='extend' then
   if p_new_ends_at is null or p_new_ends_at<=now() or (v_old_end is not null and p_new_ends_at<=v_old_end)
     or (v_d.parent_envelope_id is not null and not exists(select 1 from iam.delegation_envelopes p
       where p.tenant_id=p_tenant_id and p.id=v_d.parent_envelope_id and p.status='active'
         and (p.ends_at is null or p_new_ends_at<=p.ends_at))) then
     raise exception 'delegation_extension_outside_parent_or_expired' using errcode='22023'; end if;
   update iam.delegation_envelopes set ends_at=p_new_ends_at where tenant_id=p_tenant_id and id=p_envelope_id;
 else
   if v_old_end is null or v_old_end>now() or p_new_ends_at is not null then
     raise exception 'delegation_not_expired' using errcode='22023'; end if;
 end if;
 insert into iam.delegation_review_events(tenant_id,envelope_id,actor_user_id,action,previous_ends_at,new_ends_at,reason)
  values(p_tenant_id,p_envelope_id,v_actor,p_action,v_old_end,case when p_action='extend' then p_new_ends_at end,btrim(p_reason));
end $function$
;
CREATE OR REPLACE FUNCTION api.revoke_delegation(p_tenant_id uuid, p_envelope_id uuid, p_reason text)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_creator uuid; v_count integer;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
   raise exception 'delegation_revoke_invalid' using errcode='22023'; end if;
 select created_by into v_creator from iam.delegation_envelopes where tenant_id=p_tenant_id and id=p_envelope_id;
 if v_creator is null or (v_creator<>v_actor and not private.platform_permission_allowed('delegation.revoke')) then
   raise exception 'delegation_revoke_not_authorized' using errcode='42501'; end if;
 v_count:=private.revoke_delegation_tree(p_tenant_id,p_envelope_id,v_actor,btrim(p_reason),false);
 insert into iam.delegation_review_events(tenant_id,envelope_id,actor_user_id,action,previous_ends_at,reason)
  select p_tenant_id,p_envelope_id,v_actor,'revoke',d.ends_at,btrim(p_reason)
    from iam.delegation_envelopes d where d.tenant_id=p_tenant_id and d.id=p_envelope_id;
 return v_count;
end $function$
;
CREATE OR REPLACE FUNCTION api.revoke_entitlement_grant(p_grant_id uuid, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if not private.platform_permission_allowed('entitlement.revoke') or length(btrim(coalesce(p_reason,'')))<3 then raise exception 'grant_revocation_not_allowed' using errcode='42501'; end if;
 update core.entitlement_grants set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=p_reason where id=p_grant_id and revoked_at is null;
 if not found then raise exception 'grant_not_active' using errcode='22023'; end if;
end $function$
;
CREATE OR REPLACE FUNCTION api.set_entitlement_grant_status(p_grant_id uuid, p_status text, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_tenant uuid; v_old_status text;
begin
 if not private.platform_permission_allowed('entitlement.status') or p_status not in ('active','suspended')
   or length(btrim(coalesce(p_reason,'')))<3 then
   raise exception 'grant_status_update_not_allowed' using errcode='42501';
 end if;
 select tenant_id,status into v_tenant,v_old_status from core.entitlement_grants
   where id=p_grant_id and revoked_at is null for update;
 if not found then raise exception 'grant_not_found_or_revoked' using errcode='22023'; end if;
 if v_old_status=p_status then return; end if;
 update core.entitlement_grants set status=p_status where id=p_grant_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(null,auth.uid(),'platform','core.entitlement_grants.status_changed','core.entitlement_grants',p_grant_id,
   jsonb_build_object('tenant_id',v_tenant,'before_status',v_old_status,'after_status',p_status,'reason',p_reason));
end $function$
;
CREATE OR REPLACE FUNCTION api.set_feature_enabled(p_feature_key text, p_enabled boolean)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if not private.platform_permission_allowed('feature.toggle') then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 update core.features set enabled=p_enabled where feature_key=p_feature_key;
 if not found then raise exception 'feature_not_found' using errcode='22023'; end if;
end $function$
;
CREATE OR REPLACE FUNCTION api.set_membership_status(p_tenant_id uuid, p_membership_id uuid, p_status text, p_actor_user_id uuid, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_old_status text;
  v_member_role text;
  v_target_user uuid;
  v_actor_membership uuid;
  v_is_platform_operator boolean;
begin
  if auth.role() is distinct from 'service_role'
     or p_tenant_id is null or p_membership_id is null or p_actor_user_id is null
     or p_status is null or p_status not in ('suspended','ended')
     or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
    raise exception 'membership_status_change_not_allowed' using errcode='42501';
  end if;

  select m.status,m.member_role,m.user_id
    into v_old_status,v_member_role,v_target_user
    from iam.memberships m
   where m.tenant_id=p_tenant_id and m.id=p_membership_id
   for update;
  if not found then
    raise exception 'membership_not_found' using errcode='22023';
  end if;

  if not ((p_status='suspended' and v_old_status='active')
       or (p_status='ended' and v_old_status in ('active','suspended'))) then
    raise exception 'invalid_membership_status_transition' using errcode='23514';
  end if;

  select exists(select 1 from iam.platform_operators po
    where po.user_id=p_actor_user_id and po.active)
    into v_is_platform_operator;

  if v_is_platform_operator then
    if not private.platform_permission_allowed('membership.lifecycle',p_actor_user_id)
     or (v_member_role='company_superadmin' and not exists(select 1 from iam.platform_operators where user_id=p_actor_user_id and active and operator_role='owner')) then
     raise exception 'platform_membership_permission_required' using errcode='42501';end if;
  end if;
  if not v_is_platform_operator then
    select m.id into v_actor_membership
      from iam.memberships m
      join core.tenants t on t.id=m.tenant_id
     where m.tenant_id=p_tenant_id and m.user_id=p_actor_user_id
       and m.member_role='company_superadmin' and m.status='active' and t.status='active';

    if v_actor_membership is null or v_target_user=p_actor_user_id
       or v_member_role='company_superadmin' then
      raise exception 'company_superadmin_required_for_membership_status' using errcode='42501';
    end if;
  end if;

  update iam.memberships
     set status=p_status,updated_at=now()
   where tenant_id=p_tenant_id and id=p_membership_id;

  insert into audit.events(
    tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary
  ) values (
    p_tenant_id,p_actor_user_id,v_actor_membership,'tenant','iam.membership.status_changed',
    'iam.memberships',p_membership_id,
    jsonb_build_object('before_status',v_old_status,'after_status',p_status,'reason',btrim(p_reason))
  );
end $function$
;
CREATE OR REPLACE FUNCTION api.set_module_enabled(p_module_key text, p_enabled boolean)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if not private.platform_permission_allowed('module.toggle') then raise exception 'insufficient_privilege' using errcode='42501'; end if;
 update core.modules set enabled=p_enabled where module_key=p_module_key;
 if not found then raise exception 'module_not_found' using errcode='22023'; end if;
end $function$
;
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
   or not (p_capability_key in ('role_assignment','direct_permission_decision','scope_management','permissions.specific_override')
       or exists(select 1 from iam.permission_catalog pc where pc.permission_key=p_capability_key and pc.module_key='hse'))
   or not exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=p_membership_id
       and m.member_role='company_superadmin' and m.status='active') then
   raise exception 'superadmin_capability_limit_not_authorized' using errcode='42501';
 end if;
 insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
  values(p_tenant_id,p_membership_id,p_capability_key,p_can_use,p_can_delegate,v_actor,btrim(p_reason))
  on conflict(tenant_id,membership_id,capability_key) do update set can_use=excluded.can_use,
   can_delegate=excluded.can_delegate,set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,'tenant','iam.superadmin_capability_limit.set','iam.superadmin_capability_limits',p_membership_id,
    jsonb_build_object('capability_key',p_capability_key,'can_use',p_can_use,'can_delegate',p_can_delegate,'reason',btrim(p_reason)));
end $function$
;
CREATE OR REPLACE FUNCTION api.update_subscription_status(p_subscription_id uuid, p_status text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_sub core.subscriptions%rowtype; v_allowed boolean;
begin
 if not private.platform_permission_allowed('subscription.update') or p_status not in ('trialing','active','past_due','suspended','canceled','expired') then
   raise exception 'subscription_update_not_allowed' using errcode='42501';
 end if;
 select * into v_sub from core.subscriptions where id=p_subscription_id for update;
 if not found then raise exception 'subscription_not_found_or_final' using errcode='22023'; end if;
 if p_status=v_sub.status then return; end if;
 v_allowed:=case v_sub.status
   when 'trialing' then p_status in ('active','past_due','suspended','canceled','expired')
   when 'active' then p_status in ('past_due','suspended','canceled','expired')
   when 'past_due' then p_status in ('active','suspended','canceled','expired')
   when 'suspended' then p_status in ('active','past_due','canceled','expired')
   else false
 end;
 if not v_allowed then raise exception 'subscription_transition_not_allowed' using errcode='23514'; end if;
 if p_status in ('active','trialing') and
    (v_sub.starts_at>now() or v_sub.current_period_start>now() or v_sub.current_period_end<=now()
     or not exists(select 1 from core.plans p where p.id=v_sub.plan_id and p.status='active')) then
   raise exception 'subscription_period_or_plan_not_effective' using errcode='23514';
 end if;
 update core.subscriptions set status=p_status,
   canceled_at=case when p_status='canceled' then coalesce(canceled_at,now()) else null end
 where id=v_sub.id;
end $function$
;
CREATE OR REPLACE FUNCTION api.platform_set_tenant_status(p_tenant_id uuid, p_status text, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_previous text;
begin
 if not private.platform_permission_allowed('company.lifecycle') then raise exception 'platform_tenant_status_not_authorized' using errcode='42501';end if;
 if p_status is null or p_status not in ('active','suspended','closed') or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_tenant_status_invalid' using errcode='22023';end if;
 if p_status='closed' and not private.is_platform_owner() then raise exception 'company_close_owner_only' using errcode='42501';end if;
 select status into v_previous from core.tenants where id=p_tenant_id for update;
 if not found or v_previous='closed' then raise exception 'active_or_suspended_company_required' using errcode='23514';end if;
 update core.tenants set status=p_status where id=p_tenant_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','platform.tenant.status_changed','core.tenants',p_tenant_id,
  jsonb_build_object('previous_status',v_previous,'status',p_status,'reason',btrim(p_reason)));
end $function$
;
create or replace function api.platform_rename_tenant(p_tenant_id uuid,p_name text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_owner() then raise exception 'company_rename_owner_only' using errcode='42501';end if;
 if p_name is null or length(btrim(p_name)) not between 1 and 200 or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'company_rename_invalid' using errcode='22023';end if;
 update core.tenants set name=btrim(p_name) where id=p_tenant_id;
 if not found then raise exception 'company_not_found' using errcode='22023';end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','platform.tenant.renamed','core.tenants',p_tenant_id,jsonb_build_object('name',btrim(p_name),'reason',btrim(p_reason)));
end $$;
revoke all on function api.platform_rename_tenant(uuid,text,text) from public,anon,service_role;
grant execute on function api.platform_rename_tenant(uuid,text,text) to authenticated;
-- The fixed permission check is statement-local in restrictive read policies.
do $$declare r record;begin
 for r in select schemaname,tablename,policyname from pg_policies where policyname='platform_company_read_audit_boundary' loop
  execute format('alter policy %I on %I.%I using(not (select private.is_platform_operator()))',r.policyname,r.schemaname,r.tablename);
 end loop;
end $$;
commit;
