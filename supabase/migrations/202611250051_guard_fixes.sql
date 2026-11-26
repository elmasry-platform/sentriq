-- 051: two guard fixes found in the 048-050 audit. Plain PostgreSQL, three function bodies, no table or data change.
-- (1) A member who holds an operator-origin (protected_origin) active decision could not be suspended by anyone:
--     reset_contract_authorizations sets the member decisions to 'suspended' and guard_decision_authority refused it
--     (operator_decision_requires_operator). The guard now allows exactly one change, active -> suspended, when it comes
--     from that cascade (nested trigger, local setting on), only for a signed-in platform operator
--     (private.is_platform_operator(), the check 040 uses), and only if every column except status and updated_at is
--     unchanged. A company admin, or a service_role call through api.set_membership_status (auth.uid() is null there),
--     behaves exactly as before 051: the suspend of a member with a protected decision is refused.
--     Re-activating a protected decision still needs an operator.
-- (2) api.revoke_role_assignment had no operator path, so a superadmin single assignment could not be revoked by anyone.
--     A platform operator holding member.permissions now skips the company envelope checks. Everyone else is unchanged.

CREATE OR REPLACE FUNCTION private.guard_decision_authority()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if private.migration_runner_active() then return new; end if;
 if private.operator_decision_actor() is not null then return new; end if;
 if tg_op='UPDATE' and pg_trigger_depth()>=2 and current_setting('sentriq.member_lifecycle_suspend',true)='on'
  and private.is_platform_operator()
  and old.status='active' and new.status='suspended'
  and (to_jsonb(new)-'status'-'updated_at') = (to_jsonb(old)-'status'-'updated_at')
  then return new; end if;
 if tg_op='INSERT' and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_initial_decision',true)='on'
  and new.scope_kind='tenant' and new.reason like 'Invitation initial access:%' then return new; end if;
 if tg_op='UPDATE' and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_initial_decision',true)='on'
  and new.status='revoked' and new.revoke_reason like 'Replaced by invitation initial access:%' then return new; end if;
 if tg_op='INSERT' and new.protected_origin then
  raise exception 'protected_origin_requires_operator' using errcode='42501'; end if;
 if tg_op='INSERT' and new.decision='deny' and new.scope_kind='tenant'
  and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_restriction_deny',true)='on'
  and new.reason like 'Superadmin invitation restriction:%' then return new; end if;
 if tg_op='INSERT' then
  perform private.assert_permission_grantable(new.tenant_id,new.permission_key,new.can_write,new.site_id,new.org_unit_id,new.task_kind,new.task_id);
 else
  if new.protected_origin is distinct from old.protected_origin then
   raise exception 'protected_origin_requires_operator' using errcode='42501'; end if;
  if old.protected_origin and (new.status is distinct from old.status or new.decision is distinct from old.decision
     or new.starts_at is distinct from old.starts_at or new.ends_at is distinct from old.ends_at
     or new.can_read is distinct from old.can_read or new.can_write is distinct from old.can_write) then
   raise exception 'operator_decision_requires_operator' using errcode='42501'; end if;
  if old.decision='deny' and old.status='active' and new.status<>'active' then
   if exists(select 1 from iam.memberships m where m.tenant_id=old.tenant_id and m.id=old.membership_id
        and m.user_id=private.request_actor_id()) then
    raise exception 'own_restriction_cannot_be_cleared' using errcode='42501'; end if;
   if private.deny_locked_for(old.id,private.request_actor_id()) then
    raise exception 'deny_removal_requires_setter_subowner_or_owner' using errcode='42501'; end if;
   if old.granted_by is distinct from private.request_actor_id() and not private.can_manage_tenant(old.tenant_id) then
    raise exception 'deny_removal_requires_creator_or_superadmin' using errcode='42501'; end if;
  end if;
 end if;
 return new;
end $function$;

CREATE OR REPLACE FUNCTION private.reset_contract_authorizations()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if old.status is distinct from new.status and (new.status in ('suspended','ended') or old.status in ('suspended','ended')) then
  perform set_config('sentriq.member_lifecycle_suspend','on',true);
  update iam.member_permission_decisions set status='suspended' where tenant_id=new.tenant_id and membership_id=new.id and status='active';
  perform set_config('sentriq.member_lifecycle_suspend','off',true);
  update iam.permission_action_grants set status='suspended' where tenant_id=new.tenant_id and membership_id=new.id and status='active';
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and membership_id=new.id and is_current;
 end if;
 if old.member_role is distinct from new.member_role then
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and membership_id=new.id and is_current
   and (new.member_role='company_superadmin' or role_family<>case when new.member_role='employee' then 'employee' else 'admin' end);
 end if;
 return new;
end $function$;

CREATE OR REPLACE FUNCTION api.revoke_role_assignment(p_tenant_id uuid, p_assignment_id uuid, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare a iam.membership_roles%rowtype;b record;
 v_op boolean:=auth.uid() is not null and private.is_platform_operator() and private.platform_permission_allowed('member.permissions');
begin
 select * into a from iam.membership_roles where tenant_id=p_tenant_id and id=p_assignment_id for update;
 if not found or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'invalid_assignment_revocation' using errcode='22023';end if;
 if not v_op and exists(select 1 from iam.role_version_permissions p where p.role_version_id=a.role_version_id and p.scope_kind='tenant')
  and not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id) then
  raise exception 'assignment_revocation_outside_envelope' using errcode='42501';end if;
 for b in select site_id from iam.membership_role_sites where tenant_id=p_tenant_id and membership_role_id=a.id and revoked_at is null and not v_op loop
  if not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id,b.site_id,null) then
   raise exception 'assignment_revocation_outside_site' using errcode='42501';end if;
 end loop;
 for b in select org_unit_id from iam.membership_role_org_units where tenant_id=p_tenant_id and membership_role_id=a.id and revoked_at is null and not v_op loop
  if not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id,null,b.org_unit_id) then
   raise exception 'assignment_revocation_outside_org' using errcode='42501';end if;
 end loop;
 if not v_op and not private.can_manage_tenant(p_tenant_id) and not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id) then
  raise exception 'assignment_revocation_not_authorized' using errcode='42501';end if;
 if not v_op and private.superadmin_target_blocked(p_tenant_id,a.membership_id) then raise exception 'superadmin_target_requires_operator' using errcode='42501'; end if;
 if a.suspended_by_tenant then
  update iam.membership_roles set suspended_by_tenant=false where tenant_id=p_tenant_id and id=a.id;
 elsif a.revoked_at is null then
 update iam.membership_roles set revoked_at=coalesce(revoked_at,now()),revoked_by=coalesce(revoked_by,private.request_actor_id()),
  revoke_reason=coalesce(revoke_reason,btrim(p_reason)) where tenant_id=p_tenant_id and id=a.id;
 end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.membership_role.revoked','iam.membership_roles',a.id,jsonb_build_object('reason',btrim(p_reason),'by_operator',v_op));
end $function$;
