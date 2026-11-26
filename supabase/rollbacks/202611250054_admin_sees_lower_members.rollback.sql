-- Rollback of 054: restore the 053-era policy and function text exactly.
drop policy if exists membership_read on iam.memberships;
create policy membership_read on iam.memberships for select to authenticated
 using ((user_id = (select auth.uid())) or private.can_manage_tenant(tenant_id));
drop function if exists private.is_active_company_admin(uuid);

CREATE OR REPLACE FUNCTION api.company_member_permission_decisions(p_tenant_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_rows jsonb; v_actor uuid := private.request_actor_id(); v_event bigint;
begin
 if p_tenant_id is null
    or not (private.is_platform_operator()
            or exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
                       where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active'
                         and m.member_role in ('company_superadmin','company_admin'))) then
   raise exception 'company_decisions_read_not_authorized' using errcode='42501';
 end if;
 select coalesce(jsonb_agg(to_jsonb(page)),'[]'::jsonb) into v_rows from (
   select d.id, d.membership_id, d.permission_key, d.decision, d.can_read, d.can_write,
          d.reason, d.created_at, u.email as granted_by_email
     from iam.member_permission_decisions d
     left join auth.users u on u.id = d.granted_by
    where d.tenant_id = p_tenant_id and d.status = 'active' and d.scope_kind = 'tenant'
    order by d.created_at desc limit 500) page;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,'tenant','iam.permission_decision.listed','iam.member_permission_decisions',p_tenant_id,
        jsonb_build_object('returned',jsonb_array_length(v_rows))) returning id into v_event;
 return jsonb_build_object('rows',v_rows,'audit_event_id',v_event);
end $function$;
