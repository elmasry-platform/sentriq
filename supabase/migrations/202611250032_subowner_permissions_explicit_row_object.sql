-- Owner read RPC: return the explicit grant as an object (or null), so the UI can
-- distinguish "default" from an explicit granted=false row.
create or replace function api.platform_subowner_permissions(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb;
begin
 if not private.is_platform_owner() then raise exception 'only_owner_can_read_platform_permissions' using errcode='42501';end if;
 if not exists(select 1 from iam.platform_operators where user_id=p_user_id and operator_role='subowner') then
  raise exception 'subowner_not_found' using errcode='22023';end if;
 select coalesce(jsonb_agg(jsonb_build_object(
   'permission_key',c.permission_key,
   'granted',private.platform_permission_allowed(c.permission_key,p_user_id),
   'explicit_row',case when g.user_id is not null then jsonb_build_object('granted',g.granted,'reason',g.reason,'updated_at',g.updated_at) end
 ) order by c.permission_key), '[]'::jsonb)
 into v_rows
 from iam.platform_permission_catalog c
 left join iam.platform_permission_grants g on g.user_id=p_user_id and g.permission_key=c.permission_key;
 return jsonb_build_object('rows',v_rows);
end $$;

revoke all on function api.platform_subowner_permissions(uuid) from public,anon,service_role;
grant execute on function api.platform_subowner_permissions(uuid) to authenticated;
