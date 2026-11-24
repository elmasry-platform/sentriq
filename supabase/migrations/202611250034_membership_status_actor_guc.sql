-- Align the table-level superadmin guard with the audited service path.
-- The membership_identity_guard trigger reads the JWT actor (auth.uid()), which
-- is null on the backend's service_role connection, so api.set_membership_status
-- could not suspend a superadmin even for a validated owner/sub-owner actor.
-- The audited function now publishes its already-validated actor as a
-- transaction-local setting and the guard accepts it. Direct table writes stay
-- impossible: iam.memberships has no grants to API roles, so the only mutation
-- paths are the audited api.* functions.

create or replace function private.guard_membership_identity() returns trigger
language plpgsql set search_path = '' as $$
declare v_actor uuid;
begin
  if new.tenant_id is distinct from old.tenant_id or new.user_id is distinct from old.user_id then
    raise exception 'membership identity is immutable' using errcode='23514';
  end if;
  if old.member_role='company_superadmin' and old.status='active' and new.status<>'active' then
    v_actor := nullif(current_setting('sentriq.actor_user_id', true), '')::uuid;
    if not (private.is_platform_operator()
            or (v_actor is not null and exists(select 1 from iam.platform_operators po where po.user_id=v_actor and po.active))) then
      raise exception 'only a platform operator can deactivate the company superadmin' using errcode='42501';
    end if;
  end if;
  return new;
end $$;

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
  v_actor_operator_role text;
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

  select po.operator_role into v_actor_operator_role
    from iam.platform_operators po
   where po.user_id=p_actor_user_id and po.active;

  if v_actor_operator_role = 'owner' then
    null; -- owner is always allowed
  elsif v_actor_operator_role = 'subowner' then
    -- sub-owner follows the withdrawable membership.lifecycle gate,
    -- same as api.platform_set_membership_status.
    if not private.platform_permission_allowed('membership.lifecycle', p_actor_user_id) then
      raise exception 'platform_membership_lifecycle_not_authorized' using errcode='42501';
    end if;
  else
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

  -- Publish the validated actor for table-level guards (transaction-local).
  perform set_config('sentriq.actor_user_id', p_actor_user_id::text, true);

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
