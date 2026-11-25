-- Rollback for 048: restore the six previous function bodies, drop the triggers and helpers.
drop trigger if exists a00_superadmin_target_guard on iam.member_permissions;
drop trigger if exists a00_superadmin_target_guard on iam.membership_roles;
drop trigger if exists a00_superadmin_target_guard on iam.membership_role_sites;
drop trigger if exists a00_superadmin_target_guard on iam.membership_role_org_units;
drop trigger if exists a00_superadmin_target_guard on iam.site_access;
drop trigger if exists a00_superadmin_target_guard on iam.org_unit_access;
drop trigger if exists a00_superadmin_target_guard on iam.task_assignments;

CREATE OR REPLACE FUNCTION api.revoke_role_assignment(p_tenant_id uuid, p_assignment_id uuid, p_reason text)
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
 if a.suspended_by_tenant then
  update iam.membership_roles set suspended_by_tenant=false where tenant_id=p_tenant_id and id=a.id;
 elsif a.revoked_at is null then
 update iam.membership_roles set revoked_at=coalesce(revoked_at,now()),revoked_by=coalesce(revoked_by,private.request_actor_id()),
  revoke_reason=coalesce(revoke_reason,btrim(p_reason)) where tenant_id=p_tenant_id and id=a.id;
 end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.membership_role.revoked','iam.membership_roles',a.id,jsonb_build_object('reason',btrim(p_reason)));
end $function$;

CREATE OR REPLACE FUNCTION api.assign_engagement_supervisor(p_tenant_id uuid, p_engagement_id uuid, p_membership_id uuid, p_ends_at timestamp with time zone, p_reason text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare e hse.person_engagements%rowtype;v_id uuid;
begin
 select * into e from hse.person_engagements where tenant_id=p_tenant_id and id=p_engagement_id and status='active' for key share;
 if not found or not private.phase1_can_manage(p_tenant_id,'scope_management',p_membership_id,e.site_id,e.org_unit_id)
  or not api.authorize(p_tenant_id,'hse.people.assigned','read',e.site_id,e.org_unit_id)
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or (p_ends_at is not null and p_ends_at<=now())
  or not exists(select 1 from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and status='active') then
  raise exception 'supervisor_assignment_not_authorized' using errcode='42501'; end if;
 insert into iam.engagement_supervisors(tenant_id,membership_id,engagement_id,ends_at,created_by,reason)
 values(p_tenant_id,p_membership_id,p_engagement_id,p_ends_at,private.request_actor_id(),btrim(p_reason)) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'assigned_task','iam.engagement_supervisor.assigned','iam.engagement_supervisors',v_id,
  jsonb_build_object('engagement_id',p_engagement_id,'membership_id',p_membership_id,'reason',btrim(p_reason)));
 return v_id;
end $function$;

CREATE OR REPLACE FUNCTION api.create_delegation(p_tenant_id uuid, p_delegate_membership_id uuid, p_level text, p_site_id uuid, p_org_unit_id uuid, p_allowed_capabilities text[], p_starts_at timestamp with time zone, p_ends_at timestamp with time zone, p_reason text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_grantor uuid; v_parent uuid; v_id uuid; c text;
begin
 select m.id into v_grantor from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active'
    and private.has_member_module_entitlement(p_tenant_id,m.id,'hse');
 if v_actor is null or v_grantor is null or p_allowed_capabilities is null or cardinality(p_allowed_capabilities)=0
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_starts_at is null or (p_ends_at is not null and p_ends_at<=p_starts_at) then
   raise exception 'delegation_request_invalid' using errcode='22023';
 end if;
 foreach c in array p_allowed_capabilities loop
   if not private.phase1_can_manage(p_tenant_id,c,p_delegate_membership_id,p_site_id,p_org_unit_id) then
     raise exception 'delegation_capability_not_authorized' using errcode='42501';
   end if;
 end loop;
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=v_grantor and m.member_role<>'company_superadmin') then
   select d.id into v_parent from iam.delegation_envelopes d where d.tenant_id=p_tenant_id
    and d.delegate_membership_id=v_grantor and d.status='active' and d.starts_at<=now()
    and (d.ends_at is null or now()<d.ends_at)
    and p_allowed_capabilities <@ d.allowed_capabilities
    and ((d.level='tenant') or (d.level='employees_default' and p_level='employees_default')
      or (d.level='site' and p_level='site' and d.site_id=p_site_id)
      or (d.level='org_unit' and p_level='org_unit' and d.org_unit_id=p_org_unit_id))
    and (d.ends_at is null or (p_ends_at is not null and p_ends_at<=d.ends_at))
    order by d.created_at desc limit 1;
   if v_parent is null then raise exception 'delegation_parent_envelope_required' using errcode='42501'; end if;
 end if;
 insert into iam.delegation_envelopes(tenant_id,grantor_membership_id,delegate_membership_id,level,site_id,org_unit_id,
   allowed_capabilities,starts_at,ends_at,parent_envelope_id,created_by)
 values(p_tenant_id,v_grantor,p_delegate_membership_id,p_level,p_site_id,p_org_unit_id,p_allowed_capabilities,
   p_starts_at,p_ends_at,v_parent,v_actor) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_grantor,p_level,'iam.delegation.created','iam.delegation_envelopes',v_id,
   jsonb_build_object('delegate_membership_id',p_delegate_membership_id,'capabilities',p_allowed_capabilities,'reason',btrim(p_reason)));
 return v_id;
end $function$;

CREATE OR REPLACE FUNCTION api.delegate_member_entitlement(p_tenant_id uuid, p_source_grant_id uuid, p_target_membership_id uuid, p_reason text, p_expires_at timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid:=auth.uid(); v_am iam.memberships%rowtype; s core.entitlement_grants%rowtype; v_exp timestamptz; v_id uuid;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'entitlement_delegation_not_authorized' using errcode='42501'; end if;
 select m.* into v_am from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active';
 select * into s from core.entitlement_grants where id=p_source_grant_id and tenant_id=p_tenant_id;
 if v_am.id is null or s.id is null or s.membership_id is distinct from v_am.id or s.delegated_from_grant_id is not null
   or not s.can_use or not s.can_delegate or not private.entitlement_grant_live(s.id)
   or p_target_membership_id=v_am.id
   or (case when s.feature_key is not null then private.member_feature_state(p_tenant_id,v_am.id,s.feature_key)
            else private.member_module_state(p_tenant_id,v_am.id,s.module_key) end) not in ('company','personal_exception')
   or not exists(select 1 from iam.memberships tm where tm.tenant_id=p_tenant_id and tm.id=p_target_membership_id and tm.status='active') then
  raise exception 'entitlement_delegation_not_authorized' using errcode='42501'; end if;
 v_exp:=coalesce(p_expires_at,s.expires_at);
 if s.expires_at is not null and (v_exp is null or v_exp>s.expires_at) then
  raise exception 'delegation_cannot_outlive_source' using errcode='22023'; end if;
 if v_exp is not null and v_exp<=now() then raise exception 'delegation_expiry_in_past' using errcode='22023'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-member-entitlement:'||p_tenant_id::text||':'||p_target_membership_id::text,0));
 insert into core.entitlement_grants(tenant_id,module_key,feature_key,membership_id,starts_at,expires_at,granted_by,reason,
   billing_treatment,quota,can_use,can_delegate,delegated_from_grant_id,delegated_by)
 values(p_tenant_id,s.module_key,s.feature_key,p_target_membership_id,now(),v_exp,v_actor,btrim(p_reason),
   case when s.billing_treatment='tenant_billable' then 'platform_absorbed' else s.billing_treatment end,
   s.quota,true,false,s.id,v_actor) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,v_am.id,'tenant','iam.entitlement_delegation.created','core.entitlement_grants',v_id,
  jsonb_build_object('source_grant_id',s.id,'target_membership_id',p_target_membership_id,'module_key',s.module_key,
   'feature_key',s.feature_key,'expires_at',v_exp,'reason',btrim(p_reason)));
 return v_id;
end $function$;

CREATE OR REPLACE FUNCTION api.revoke_invitation(p_invitation_id uuid, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_t uuid;
begin
 update iam.invitations set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=btrim(p_reason)
 where id=p_invitation_id and accepted_at is null and revoked_at is null and length(btrim(coalesce(p_reason,'')))>=3
   and ((private.is_platform_operator() and private.platform_permission_allowed('superadmin.invite')) or private.is_company_superadmin_of(tenant_id))
 returning tenant_id into v_t;
 if v_t is null then raise exception 'invitation_not_found_or_final' using errcode='22023'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(v_t,auth.uid(),'tenant','iam.invitation.revoked','iam.invitations',p_invitation_id,jsonb_build_object('reason',btrim(p_reason)));
end $function$;

CREATE OR REPLACE FUNCTION api.clear_member_permission_decision(p_tenant_id uuid, p_membership_id uuid, p_permission_key text, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_actor uuid := private.request_actor_id(); v_count int;
begin
 if v_actor is null
    or p_reason is null or length(btrim(p_reason)) not between 3 and 500
    or not exists(select 1 from iam.memberships t where t.tenant_id=p_tenant_id and t.id=p_membership_id)
    or not private.phase1_can_manage(p_tenant_id,'direct_permission_decision',p_membership_id) then
   raise exception 'direct_permission_clear_not_allowed' using errcode='42501';
 end if;

 if exists(select 1 from iam.memberships own where own.tenant_id=p_tenant_id and own.id=p_membership_id and own.user_id=v_actor) then
   raise exception 'own_membership_decision_not_allowed' using errcode='42501'; end if;
 if exists(select 1 from iam.member_permission_decisions pd where pd.tenant_id=p_tenant_id and pd.membership_id=p_membership_id
    and pd.permission_key=p_permission_key and pd.status='active' and pd.protected_origin) then
   raise exception 'operator_decision_requires_operator' using errcode='42501'; end if;
 if exists(select 1 from iam.member_permission_decisions ld where ld.tenant_id=p_tenant_id and ld.membership_id=p_membership_id
    and ld.permission_key=p_permission_key and ld.scope_kind='tenant' and private.deny_locked_for(ld.id,v_actor)) then
   raise exception 'deny_removal_requires_setter_subowner_or_owner' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-decision:'||p_tenant_id::text||':'||p_membership_id::text||':'||p_permission_key,0));
 update iam.member_permission_decisions d
    set status='revoked', revoked_at=now(), revoked_by=v_actor, revoke_reason=btrim(p_reason)
  where d.tenant_id=p_tenant_id and d.membership_id=p_membership_id
    and d.permission_key=p_permission_key and d.scope_kind='tenant' and d.status='active';
 get diagnostics v_count = row_count;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,'tenant','iam.permission_decision.cleared','iam.member_permission_decisions',p_membership_id,
        jsonb_build_object('permission_key',p_permission_key,'cleared',v_count,'reason',btrim(p_reason)));
end $function$;
drop function if exists private.guard_superadmin_target_rows();
drop function if exists private.superadmin_target_blocked(uuid,uuid);
