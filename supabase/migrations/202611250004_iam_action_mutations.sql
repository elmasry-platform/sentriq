-- Narrow APIs for named actions. Existing read/write APIs remain compatible.
begin;
create or replace function api.set_permission_action(p_tenant_id uuid,p_membership_id uuid,p_permission_key text,
 p_action text,p_decision text,p_scope_kind text,p_site_id uuid,p_org_unit_id uuid,p_task_kind text,p_task_id uuid,
 p_starts_at timestamptz,p_ends_at timestamptz,p_reason text) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_id uuid; v_actor uuid:=private.request_actor_id(); m iam.memberships%rowtype; v_source uuid;
begin
 if p_action in ('read','write') or p_reason is null or length(btrim(p_reason)) not between 3 and 500 or p_decision not in ('allow','deny')
  or p_starts_at is null or (p_ends_at is not null and p_ends_at<=p_starts_at)
  or not private.phase1_can_manage(p_tenant_id,'direct_permission_decision',p_membership_id,p_site_id,p_org_unit_id)
  or not exists(select 1 from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and status='active' and member_role<>'company_superadmin')
  or not exists(select 1 from iam.permission_catalog where permission_key=p_permission_key and enabled
    and p_action=any(supported_actions) and p_scope_kind=any(supported_scope_kinds))
  or not api.authorize(p_tenant_id,p_permission_key,p_action,p_site_id,p_org_unit_id,p_task_kind,p_task_id) then
  raise exception 'action_decision_not_authorized' using errcode='42501'; end if;
 select * into m from iam.memberships where tenant_id=p_tenant_id and user_id=v_actor and status='active';
 if exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id and l.membership_id=m.id
   and l.capability_key=p_permission_key and (not l.can_use or not l.can_delegate)) then
  raise exception 'action_not_delegable' using errcode='42501'; end if;
 if m.member_role<>'company_superadmin' then
  select id into v_source from iam.delegation_envelopes d where tenant_id=p_tenant_id and delegate_membership_id=m.id
   and private.decision_source_valid(d.id,d.tenant_id) and 'direct_permission_decision'=any(allowed_capabilities)
   and (level='tenant' or (level='employees_default' and exists(select 1 from iam.memberships target where target.tenant_id=p_tenant_id and target.id=p_membership_id and member_role='employee'))
    or (level='site' and p_scope_kind='site' and site_id=p_site_id) or (level='org_unit' and p_scope_kind='org_unit' and org_unit_id=p_org_unit_id))
   order by created_at desc,id limit 1;
  if v_source is null then raise exception 'exact_action_envelope_required' using errcode='42501'; end if;
 end if;
 if p_scope_kind='assigned_task' and not exists(select 1 from iam.task_assignments where tenant_id=p_tenant_id
   and membership_id=p_membership_id and task_kind=p_task_kind and task_id=p_task_id and active) then
  raise exception 'exact_task_assignment_required' using errcode='23503'; end if;
 if exists(select 1 from iam.permission_action_grants where tenant_id=p_tenant_id and membership_id=p_membership_id
   and permission_key=p_permission_key and action_key=p_action and decision='deny' and status='active'
   and scope_kind=p_scope_kind and site_id is not distinct from p_site_id and org_unit_id is not distinct from p_org_unit_id
   and task_kind is not distinct from p_task_kind and task_id is not distinct from p_task_id
   and created_by<>v_actor) and m.member_role<>'company_superadmin' then
  raise exception 'cannot_replace_another_creators_deny' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-action-decision:'||p_tenant_id::text||':'||p_membership_id::text||':'||p_permission_key||':'||p_action,0));
 update iam.permission_action_grants set status='revoked' where tenant_id=p_tenant_id and membership_id=p_membership_id
  and permission_key=p_permission_key and action_key=p_action and status='active' and scope_kind=p_scope_kind
  and site_id is not distinct from p_site_id and org_unit_id is not distinct from p_org_unit_id
  and task_kind is not distinct from p_task_kind and task_id is not distinct from p_task_id;
 insert into iam.permission_action_grants(tenant_id,membership_id,permission_key,action_key,decision,scope_kind,site_id,org_unit_id,
 task_kind,task_id,starts_at,ends_at,created_by,reason,source_delegation_id)
 values(p_tenant_id,p_membership_id,p_permission_key,p_action,p_decision,p_scope_kind,p_site_id,p_org_unit_id,
 p_task_kind,p_task_id,p_starts_at,p_ends_at,v_actor,btrim(p_reason),v_source) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,p_scope_kind,'iam.action_decision.set','iam.permission_action_grants',v_id,
 jsonb_build_object('permission_key',p_permission_key,'action',p_action,'decision',p_decision,'source_delegation_id',v_source,'reason',btrim(p_reason)));
 return v_id;
end $$;

-- Transactional role/profile action hooks. They reject action escalation even
-- if a caller has generic role/profile administration authority.
create or replace function private.guard_action_composition_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare a text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 foreach a in array new.actions loop
  if a not in ('read','write') and not api.authorize(new.tenant_id,new.permission_key,a,
   case when tg_table_name='permission_profile_permissions' then (to_jsonb(new)->>'site_id')::uuid end,
   case when tg_table_name='permission_profile_permissions' then (to_jsonb(new)->>'org_unit_id')::uuid end) then
   raise exception 'named_action_outside_grantor_authority' using errcode='42501'; end if;
 end loop;
 return new;
end $$;
create trigger action_composition_authority before insert on iam.role_version_permissions
 for each row execute function private.guard_action_composition_authority();
create trigger action_profile_composition_authority before insert on iam.permission_profile_permissions
 for each row execute function private.guard_action_composition_authority();

-- Audit each direct action state transition. No hard delete or mutable origin.
create or replace function private.guard_action_history() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if tg_op='DELETE' then raise exception 'action_history_is_append_only' using errcode='42501'; end if;
 if tg_op='UPDATE' and to_jsonb(new)-'status' is distinct from to_jsonb(old)-'status' then
  raise exception 'action_origin_and_content_immutable' using errcode='23514'; end if;
 if tg_op='UPDATE' and old.status='revoked' and new.status<>'revoked' then
  raise exception 'revoked_action_cannot_reactivate' using errcode='23514'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(new.tenant_id,private.request_actor_id(),new.scope_kind,'iam.action_decision.'||lower(tg_op),'iam.permission_action_grants',new.id,
 jsonb_build_object('status',new.status,'membership_id',new.membership_id,'source_delegation_id',new.source_delegation_id));
 return new;
end $$;
create trigger action_history_guard before update or delete on iam.permission_action_grants
 for each row execute function private.guard_action_history();

revoke all on function api.set_permission_action(uuid,uuid,text,text,text,text,uuid,uuid,text,uuid,timestamptz,timestamptz,text),
 private.guard_action_composition_authority(),private.guard_action_history() from public,anon,authenticated,service_role;
grant execute on function api.set_permission_action(uuid,uuid,text,text,text,text,uuid,uuid,text,uuid,timestamptz,timestamptz,text) to authenticated;
commit;
