-- Preserve agreed platform lifecycle powers without restoring unaudited SELECT.
begin;
create or replace function api.platform_set_tenant_status(p_tenant_id uuid,p_status text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare v_previous text;
begin
 if not private.is_platform_operator() then raise exception 'platform_tenant_status_not_authorized' using errcode='42501';end if;
 if p_status is null or p_status not in ('active','suspended') or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_tenant_status_invalid' using errcode='22023';end if;
 select status into v_previous from core.tenants where id=p_tenant_id for update;
 if not found or v_previous='closed' then raise exception 'active_or_suspended_company_required' using errcode='23514';end if;
 update core.tenants set status=p_status where id=p_tenant_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','platform.tenant.status_changed','core.tenants',p_tenant_id,
  jsonb_build_object('previous_status',v_previous,'status',p_status,'reason',btrim(p_reason)));
end $$;
revoke all on function api.platform_set_tenant_status(uuid,text,text) from public,anon,service_role;
grant execute on function api.platform_set_tenant_status(uuid,text,text) to authenticated;
commit;
