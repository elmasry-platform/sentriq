-- Forward-only membership lifecycle, entitlement scope, and function ACL hardening.
-- Existing records are preserved; unsupported member-scoped module grants stop
-- this migration with their IDs so an operator can review them explicitly.
begin;

-- Supabase migrations in this repository are applied as postgres. Default
-- EXECUTE for new routines is revoked globally from the built-in PUBLIC role,
-- and from Supabase API roles within the application schemas. Production must
-- apply this for its actual migration/object owner as well.
alter default privileges for role postgres
  revoke execute on functions from public;
alter default privileges for role postgres in schema api
  revoke execute on functions from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema private
  revoke execute on functions from public, anon, authenticated, service_role;

-- Company memberships can only be inserted/activated by trusted lifecycle
-- functions such as api.accept_invitation. Browser roles retain read access,
-- but no table-level or column-level INSERT/UPDATE/DELETE path.
drop policy if exists membership_insert on iam.memberships;
drop policy if exists membership_update on iam.memberships;
revoke all privileges on iam.memberships from anon, authenticated, service_role;
grant select on iam.memberships to authenticated;

-- Suspend or end an existing active membership through a narrow server RPC.
-- Activation, identity changes, and management-level changes are intentionally
-- unavailable here; an inactive member must accept a new verified invitation.
create or replace function api.set_membership_status(
  p_tenant_id uuid,
  p_membership_id uuid,
  p_status text,
  p_actor_user_id uuid,
  p_reason text
) returns void
language plpgsql security definer set search_path='' as $$
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
end $$;
revoke all on function api.set_membership_status(uuid,uuid,text,uuid,text)
  from public, anon, authenticated, service_role;
grant execute on function api.set_membership_status(uuid,uuid,text,uuid,text)
  to service_role;

-- Module grants are tenant-level. Report incompatible historical rows and stop
-- rather than silently changing an existing commercial record.
do $$
declare
  v_grant_ids text;
begin
  select string_agg(g.id::text,', ' order by g.id)
    into v_grant_ids
    from core.entitlement_grants g
   where g.module_key is not null and g.membership_id is not null;

  if v_grant_ids is not null then
    raise exception 'member-scoped module grants require owner review; grant IDs: %',v_grant_ids
      using errcode='23514';
  end if;
end $$;

alter table core.entitlement_grants
  add constraint entitlement_grants_module_tenant_scope
  check (module_key is null or membership_id is null);

-- Fail explicitly at the API boundary as well as the table constraint.
create or replace function api.issue_entitlement_grant(
 p_tenant_id uuid,p_module_key text,p_feature_key text,p_membership_id uuid,
 p_starts_at timestamptz,p_expires_at timestamptz,p_reason text,p_billing_treatment text,
 p_currency char(3),p_unit_price_minor bigint,p_quota numeric default null
) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_id uuid;
begin
 if not private.is_platform_operator() or p_starts_at is null or p_expires_at is null or p_starts_at>=p_expires_at
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
end $$;
revoke all on function api.issue_entitlement_grant(uuid,text,text,uuid,timestamptz,timestamptz,text,text,char,bigint,numeric)
  from public, anon, authenticated, service_role;
grant execute on function api.issue_entitlement_grant(uuid,text,text,uuid,timestamptz,timestamptz,text,text,char,bigint,numeric)
  to authenticated;

commit;

