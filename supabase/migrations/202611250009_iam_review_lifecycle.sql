-- Exact action lifecycle review and guarded revocations.
begin;
create or replace function api.revoke_permission_action(p_tenant_id uuid,p_action_id uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare d iam.permission_action_grants%rowtype;v_actor uuid:=private.request_actor_id();
begin
 select * into d from iam.permission_action_grants where tenant_id=p_tenant_id and id=p_action_id for update;
 if not found or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or (d.created_by<>v_actor and not private.can_manage_tenant(p_tenant_id)) then
  raise exception 'action_revocation_not_authorized' using errcode='42501';end if;
 update iam.permission_action_grants set status='revoked' where tenant_id=p_tenant_id and id=p_action_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,d.scope_kind,'iam.action_decision.revoked','iam.permission_action_grants',d.id,jsonb_build_object('reason',btrim(p_reason)));
end $$;
create or replace function api.adopt_permission_action(p_tenant_id uuid,p_action_id uuid,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare d iam.permission_action_grants%rowtype;v_id uuid;
begin
 select * into d from iam.permission_action_grants where tenant_id=p_tenant_id and id=p_action_id for update;
 if not found or not private.can_manage_tenant(p_tenant_id) or d.status='revoked' or d.source_delegation_id is null
  or private.decision_source_valid(d.source_delegation_id,d.tenant_id)
  or (d.ends_at is not null and d.ends_at<=now()) then
  raise exception 'action_not_pending_superadmin_adoption' using errcode='42501';end if;
 v_id:=api.set_permission_action(d.tenant_id,d.membership_id,d.permission_key,d.action_key,d.decision,d.scope_kind,
  d.site_id,d.org_unit_id,d.task_kind,d.task_id,greatest(now(),d.starts_at),d.ends_at,p_reason);
 update iam.permission_action_grants set status='revoked' where tenant_id=d.tenant_id and id=d.id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),d.scope_kind,'iam.action_decision.adopted','iam.permission_action_grants',v_id,
  jsonb_build_object('original_decision_id',d.id,'original_envelope_id',d.source_delegation_id,'reason',btrim(p_reason)));
 return v_id;
end $$;
create or replace function api.revoke_role_assignment(p_tenant_id uuid,p_assignment_id uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype;b record;
begin
 select * into a from iam.membership_roles where tenant_id=p_tenant_id and id=p_assignment_id for update;
 if not found or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'invalid_assignment_revocation' using errcode='22023';end if;
 if exists(select 1 from iam.role_version_permissions p where p.role_version_id=a.role_version_id and p.scope_kind='tenant')
  and not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id) then
  raise exception 'assignment_revocation_outside_envelope' using errcode='42501';end if;
 for b in select site_id from iam.membership_role_sites where tenant_id=p_tenant_id and membership_role_id=a.id and revoked_at is null loop
  if not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id,b.site_id,null) then
   raise exception 'assignment_revocation_outside_site' using errcode='42501';end if;
 end loop;
 for b in select org_unit_id from iam.membership_role_org_units where tenant_id=p_tenant_id and membership_role_id=a.id and revoked_at is null loop
  if not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id,null,b.org_unit_id) then
   raise exception 'assignment_revocation_outside_org' using errcode='42501';end if;
 end loop;
 if not private.can_manage_tenant(p_tenant_id) and not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id) then
  raise exception 'assignment_revocation_not_authorized' using errcode='42501';end if;
 update iam.membership_roles set revoked_at=coalesce(revoked_at,now()),revoked_by=coalesce(revoked_by,private.request_actor_id()),
  revoke_reason=coalesce(revoke_reason,btrim(p_reason)) where tenant_id=p_tenant_id and id=a.id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.membership_role.revoked','iam.membership_roles',a.id,jsonb_build_object('reason',btrim(p_reason)));
end $$;
revoke all on function api.revoke_permission_action(uuid,uuid,text),api.adopt_permission_action(uuid,uuid,text),api.revoke_role_assignment(uuid,uuid,text)
 from public,anon,authenticated,service_role;
grant execute on function api.revoke_permission_action(uuid,uuid,text),api.adopt_permission_action(uuid,uuid,text),api.revoke_role_assignment(uuid,uuid,text) to authenticated;
commit;
