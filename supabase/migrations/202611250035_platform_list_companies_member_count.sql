-- Add an active-member count to the audited platform company list so the
-- owner and sub-owner can see company size without opening each company.
create or replace function api.platform_list_companies(p_limit integer default 50,p_offset integer default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb;v_event bigint;
begin
 if not private.is_platform_operator() then raise exception 'platform_read_not_authorized' using errcode='42501';end if;
 if p_limit is null or p_limit not between 1 and 100 or p_offset is null or p_offset not between 0 and 10000 then
  raise exception 'platform_read_page_invalid' using errcode='22023';end if;
 select coalesce(jsonb_agg(to_jsonb(page)),'[]'::jsonb) into v_rows from (
  select t.id,t.name,t.industry_label,t.status,t.created_at,
   (select count(*) from iam.memberships m where m.tenant_id=t.id and m.status='active') as member_count
   from core.tenants t order by t.id limit p_limit offset p_offset) page;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,summary)
 values(null,private.request_actor_id(),'platform','platform.companies.list','core.tenants',
  jsonb_build_object('limit',p_limit,'offset',p_offset,'returned',jsonb_array_length(v_rows))) returning id into v_event;
 return jsonb_build_object('rows',v_rows,'limit',p_limit,'offset',p_offset,'audit_event_id',v_event);
end $$;
revoke all on function api.platform_list_companies(integer,integer) from public,anon,service_role;
grant execute on function api.platform_list_companies(integer,integer) to authenticated;
