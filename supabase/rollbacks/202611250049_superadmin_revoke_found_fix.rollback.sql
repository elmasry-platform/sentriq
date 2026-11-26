-- Rollback for 049: restore the 048 body of api.revoke_role_assignment (this brings the FOUND bug back).
create or replace FUNCTION api.revoke_role_assignment(p_tenant_id uuid, p_assignment_id uuid, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
 if found and private.superadmin_target_blocked(p_tenant_id,a.membership_id) then raise exception 'superadmin_target_requires_operator' using errcode='42501'; end if;
 if a.suspended_by_tenant then
  update iam.membership_roles set suspended_by_tenant=false where tenant_id=p_tenant_id and id=a.id;
 elsif a.revoked_at is null then
 update iam.membership_roles set revoked_at=coalesce(revoked_at,now()),revoked_by=coalesce(revoked_by,private.request_actor_id()),
  revoke_reason=coalesce(revoke_reason,btrim(p_reason)) where tenant_id=p_tenant_id and id=a.id;
 end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.membership_role.revoked','iam.membership_roles',a.id,jsonb_build_object('reason',btrim(p_reason)));
end $function$;
