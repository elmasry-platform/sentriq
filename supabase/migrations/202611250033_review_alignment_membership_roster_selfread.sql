-- Independent review alignment (recovera TEST):
-- 1. api.set_membership_status (backend/service path) now applies the same
--    membership.lifecycle gate as api.platform_set_membership_status for
--    sub-owners, instead of treating every active platform operator as allowed.
-- 2. api.platform_operator_roster returns the operator email so the owner UI
--    can show people instead of truncated ids.
-- 3. api.my_platform_permissions lets a sub-owner read their own current
--    permission states, so the UI can hide actions the owner has withdrawn.

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

create or replace function api.platform_operator_roster(p_limit integer default 50,p_offset integer default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb;v_event bigint;
begin
 if not private.is_platform_operator() then raise exception 'platform_read_not_authorized' using errcode='42501';end if;
 if p_limit is null or p_limit not between 1 and 100 or p_offset is null or p_offset not between 0 and 10000 then
  raise exception 'platform_read_page_invalid' using errcode='22023';end if;
 select coalesce(jsonb_agg(to_jsonb(page)),'[]'::jsonb) into v_rows from (
  select po.user_id,u.email,po.operator_role,po.active,po.created_by,po.created_at,po.deactivated_at
    from iam.platform_operators po
    left join auth.users u on u.id=po.user_id
   order by po.user_id limit p_limit offset p_offset) page;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,summary)
 values(null,private.request_actor_id(),'platform','platform.operators.list','iam.platform_operators',
  jsonb_build_object('limit',p_limit,'offset',p_offset,'returned',jsonb_array_length(v_rows))) returning id into v_event;
 return jsonb_build_object('rows',v_rows,'limit',p_limit,'offset',p_offset,'audit_event_id',v_event);
end $$;
revoke all on function api.platform_operator_roster(integer,integer) from public,anon,service_role;
grant execute on function api.platform_operator_roster(integer,integer) to authenticated;

-- A platform operator reads their own current permission states.
-- Owners are always granted everything; sub-owners see the withdrawable model.
create or replace function api.my_platform_permissions()
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb; v_role text;
begin
 select po.operator_role into v_role
   from iam.platform_operators po
  where po.user_id=private.request_actor_id() and po.active;
 if v_role is null then raise exception 'platform_operator_required' using errcode='42501'; end if;
 if v_role = 'owner' then
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',true) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 else
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',private.platform_permission_allowed(c.permission_key,private.request_actor_id())) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 end if;
 return jsonb_build_object('rows',v_rows);
end $$;
revoke all on function api.my_platform_permissions() from public,anon,service_role;
grant execute on function api.my_platform_permissions() to authenticated;
