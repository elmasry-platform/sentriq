-- Audited read of a company's member permission decisions and an audited
-- "clear back to default" path, so the redesigned People & access screen can
-- show who has what and undo an explicit decision. Same manage gate as
-- api.set_member_permission_decision; platform operators keep their read path.

create or replace function api.company_member_permission_decisions(p_tenant_id uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb; v_actor uuid := private.request_actor_id(); v_event bigint;
begin
 if p_tenant_id is null
    or not (private.is_platform_operator()
            or exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
                       where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active')) then
   raise exception 'company_decisions_read_not_authorized' using errcode='42501';
 end if;
 select coalesce(jsonb_agg(to_jsonb(page)),'[]'::jsonb) into v_rows from (
   select d.id, d.membership_id, d.permission_key, d.decision, d.can_read, d.can_write,
          d.reason, d.created_at, u.email as granted_by_email
     from iam.member_permission_decisions d
     left join auth.users u on u.id = d.granted_by
    where d.tenant_id = p_tenant_id and d.status = 'active' and d.scope_kind = 'tenant'
    order by d.created_at desc limit 500) page;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,summary)
 values(p_tenant_id,v_actor,'tenant','iam.permission_decision.listed','iam.member_permission_decisions',
        jsonb_build_object('returned',jsonb_array_length(v_rows))) returning id into v_event;
 return jsonb_build_object('rows',v_rows,'audit_event_id',v_event);
end $$;

create or replace function api.clear_member_permission_decision(
  p_tenant_id uuid, p_membership_id uuid, p_permission_key text, p_reason text
) returns void language plpgsql security definer set search_path='' as $$
declare v_actor uuid := private.request_actor_id(); v_count int;
begin
 if v_actor is null
    or p_reason is null or length(btrim(p_reason)) not between 3 and 500
    or not exists(select 1 from iam.memberships t where t.tenant_id=p_tenant_id and t.id=p_membership_id)
    or not private.phase1_can_manage(p_tenant_id,'direct_permission_decision',p_membership_id) then
   raise exception 'direct_permission_clear_not_allowed' using errcode='42501';
 end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-decision:'||p_tenant_id::text||':'||p_membership_id::text||':'||p_permission_key,0));
 update iam.member_permission_decisions d
    set status='revoked', revoked_at=now(), revoked_by=v_actor, revoke_reason=btrim(p_reason)
  where d.tenant_id=p_tenant_id and d.membership_id=p_membership_id
    and d.permission_key=p_permission_key and d.scope_kind='tenant' and d.status='active';
 get diagnostics v_count = row_count;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,'tenant','iam.permission_decision.cleared','iam.member_permission_decisions',p_membership_id,
        jsonb_build_object('permission_key',p_permission_key,'cleared',v_count,'reason',btrim(p_reason)));
end $$;

revoke all on function api.company_member_permission_decisions(uuid),
  api.clear_member_permission_decision(uuid,uuid,text,text) from public, anon, service_role;
grant execute on function api.company_member_permission_decisions(uuid),
  api.clear_member_permission_decision(uuid,uuid,text,text) to authenticated;
