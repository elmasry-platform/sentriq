begin;
create or replace function api.set_default_permission_profile(
 p_tenant_id uuid,p_role_family text,p_profile_name text,p_permissions jsonb,
 p_target_mode text,p_target_membership_ids uuid[],p_reason text
) returns table(profile_id uuid,profile_version_id uuid,default_updated boolean)
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=private.request_actor_id(); v_actor_membership uuid; v_profile uuid; v_version uuid;
        v_version_no integer; v_ids uuid[]:=coalesce(p_target_membership_ids,array[]::uuid[]);
        v_default boolean:=p_target_mode in ('new_users_only','selected_existing_and_new_users');
begin
 select m.id into v_actor_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor
    and m.status='active' and t.status='active';
 if v_actor is null or v_actor_membership is null
   or not private.phase1_can_manage(p_tenant_id,'role_assignment',null,null,null) then
   raise exception 'permission_profile_management_not_delegated' using errcode='42501'; end if;
 if p_role_family is null or p_role_family not in ('admin','employee') or p_profile_name is null or length(btrim(p_profile_name)) not between 1 and 120
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_permissions is null or jsonb_typeof(p_permissions)<>'array' or jsonb_array_length(p_permissions)>100
   or p_target_mode not in ('new_users_only','selected_existing_users','selected_existing_and_new_users') then
   raise exception 'permission_profile_request_invalid' using errcode='22023';
 end if;
 if (p_target_mode='new_users_only' and cardinality(v_ids)<>0)
   or (p_target_mode<>'new_users_only' and (cardinality(v_ids)=0 or cardinality(v_ids)<>(select count(distinct x) from unnest(v_ids) x))) then
   raise exception 'explicit_profile_target_selection_required' using errcode='22023';
 end if;
 if p_target_mode='new_users_only' and not private.phase1_can_manage(p_tenant_id,'role_assignment',null,null,null) then
   raise exception 'default_profile_management_not_delegated' using errcode='42501';
 end if;
 if (select m.member_role from iam.memberships m where m.tenant_id=p_tenant_id and m.id=v_actor_membership)<>'company_superadmin'
   and p_role_family<>'employee' then
   raise exception 'delegated_default_profile_must_target_employee_family' using errcode='42501';
 end if;
 if exists(select 1 from jsonb_array_elements(p_permissions) as e(value)
   where jsonb_typeof(e.value)<>'object' or exists(select 1 from jsonb_object_keys(e.value) as k(key)
     where k.key not in ('permission_key','scope_kind','site_id','org_unit_id','can_read','can_write','actions')))
   or exists(select 1 from jsonb_to_recordset(p_permissions) as x(
       permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean,actions text[])
     where permission_key is null or scope_kind not in ('tenant','site','org_unit') or (not coalesce(can_read,false) and not coalesce(can_write,false) and cardinality(coalesce(actions,'{}'))=0)
       or (scope_kind='site') is distinct from (site_id is not null)
       or (scope_kind='org_unit') is distinct from (org_unit_id is not null)) then
   raise exception 'permission_profile_permission_invalid' using errcode='22023';
 end if;
 if exists(select 1 from jsonb_to_recordset(p_permissions) as x(
      permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean,actions text[])
    left join iam.permission_catalog pc on pc.permission_key=x.permission_key  and pc.enabled
    where pc.permission_key is null or (pc.feature_key is not null
      and not private.has_feature_entitlement(p_tenant_id,v_actor_membership,pc.feature_key))) then
   raise exception 'permission_not_enabled_for_company' using errcode='42501';
 end if;
 if p_target_mode<>'new_users_only' and exists(
   select 1 from unnest(v_ids) as selected_membership(membership_id)
    left join iam.memberships m on m.tenant_id=p_tenant_id and m.id=selected_membership.membership_id
   where m.id is null or m.status<>'active' or m.member_role='company_superadmin'
     or (case when m.member_role='employee' then 'employee' else 'admin' end)<>p_role_family
     or not private.phase1_can_manage(p_tenant_id,'role_assignment',m.id,null,null)) then
   raise exception 'profile_target_must_be_active_matching_family_member' using errcode='42501';
 end if;
 insert into iam.permission_profiles(tenant_id,role_family,profile_name,created_by)
  values(p_tenant_id,p_role_family,btrim(p_profile_name),v_actor)
  on conflict(tenant_id,role_family) do update set profile_name=excluded.profile_name
  returning id into v_profile;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-profile-version:'||p_tenant_id::text||':'||v_profile::text,0));
 select coalesce(max(pv.version_no),0)+1 into v_version_no from iam.permission_profile_versions pv
  where pv.tenant_id=p_tenant_id and pv.profile_id=v_profile;
 insert into iam.permission_profile_versions(tenant_id,profile_id,version_no,created_by)
  values(p_tenant_id,v_profile,v_version_no,v_actor) returning id into v_version;
 insert into iam.permission_profile_permissions(tenant_id,profile_version_id,permission_key,scope_kind,site_id,org_unit_id,can_read,can_write,actions)
  select p_tenant_id,v_version,x.permission_key,x.scope_kind,x.site_id,x.org_unit_id,coalesce(x.can_read,false),coalesce(x.can_write,false),coalesce(x.actions,array_remove(array[case when x.can_read then 'read' end,case when x.can_write then 'write' end],null))
  from jsonb_to_recordset(p_permissions) as x(
    permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean,actions text[]);
 if v_default then
   insert into iam.permission_profile_defaults(tenant_id,role_family,profile_id,profile_version_id,updated_by)
    values(p_tenant_id,p_role_family,v_profile,v_version,v_actor)
    on conflict(tenant_id,role_family) do update set profile_id=excluded.profile_id,
      profile_version_id=excluded.profile_version_id,updated_by=excluded.updated_by,updated_at=now();
 end if;
 insert into iam.permission_profile_applications(tenant_id,profile_id,profile_version_id,target_mode,target_membership_ids,applied_by)
  values(p_tenant_id,v_profile,v_version,p_target_mode,v_ids,v_actor);
 if p_target_mode<>'new_users_only' then
   update iam.membership_permission_profiles set is_current=false
    where tenant_id=p_tenant_id and role_family=p_role_family and membership_id=any(v_ids) and is_current;
   insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,source,assigned_by,is_current)
    select p_tenant_id,m.id,p_role_family,v_profile,v_version,'explicit_application',v_actor,true
     from iam.memberships m where m.tenant_id=p_tenant_id and m.id=any(v_ids);
 end if;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_actor_membership,'tenant','iam.permission_profile.applied','iam.permission_profiles',v_profile,
   jsonb_build_object('role_family',p_role_family,'version_id',v_version,'target_mode',p_target_mode,'target_count',cardinality(v_ids),'reason',btrim(p_reason)));
 return query select v_profile,v_version,v_default;
end $$;

create or replace function api.set_member_permission_decision(
 p_tenant_id uuid,p_membership_id uuid,p_permission_key text,p_decision text,p_scope_kind text,
 p_site_id uuid,p_org_unit_id uuid,p_task_kind text,p_task_id uuid,p_can_read boolean,p_can_write boolean,
 p_ends_at timestamptz,p_exception_kind text,p_reason text
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=private.request_actor_id(); v_actor_membership uuid; v_id uuid; v_target iam.memberships%rowtype;
        v_feature text;
begin
 select m.id into v_actor_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active';
 select * into v_target from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id;
 if v_actor is null or v_actor_membership is null or v_target.id is null or v_target.status<>'active'
   or v_target.member_role='company_superadmin'
   or p_can_read is null or p_can_write is null
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_decision not in ('allow','deny') or p_scope_kind not in ('tenant','site','org_unit','assigned_task')
   or (p_scope_kind='site') is distinct from (p_site_id is not null)
   or (p_scope_kind='org_unit') is distinct from (p_org_unit_id is not null)
   or (p_scope_kind='assigned_task') is distinct from (p_task_id is not null and p_task_kind is not null)
   or (p_decision='deny' and (p_can_read or p_can_write or p_exception_kind is not null))
   or (p_decision='allow' and not (p_can_read or p_can_write))
   or (p_exception_kind is not null and (p_decision<>'allow' or p_exception_kind<>'specific_override')) then
   raise exception 'direct_permission_decision_invalid' using errcode='22023';
 end if;
 if not private.phase1_can_manage(p_tenant_id,'direct_permission_decision',p_membership_id,p_site_id,p_org_unit_id)
   or (p_exception_kind='specific_override' and not private.phase1_can_manage(p_tenant_id,'permissions.specific_override',p_membership_id,p_site_id,p_org_unit_id)) then
   raise exception 'direct_permission_decision_not_delegated' using errcode='42501';
 end if;
 select feature_key into v_feature from iam.permission_catalog where permission_key=p_permission_key and enabled;
 if not found then raise exception 'permission_key_not_in_enabled_catalog' using errcode='22023'; end if;
 if p_decision='allow' and v_feature is not null and not private.has_feature_entitlement(p_tenant_id,v_actor_membership,v_feature) then
   raise exception 'permission_feature_not_enabled' using errcode='42501';
 end if;
 if p_scope_kind='assigned_task' and not exists(select 1 from iam.task_assignments ta where ta.tenant_id=p_tenant_id
   and ta.membership_id=p_membership_id and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active) then
   raise exception 'task_scope_requires_active_assignment' using errcode='23503';
 end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-decision:'||p_tenant_id::text||':'||p_membership_id::text||':'||p_permission_key,0));
 update iam.member_permission_decisions d set status='revoked',revoked_at=now(),revoked_by=v_actor,
   revoke_reason='Replaced by a new authorized decision'
 where d.tenant_id=p_tenant_id and d.membership_id=p_membership_id and d.permission_key=p_permission_key
   and d.scope_kind=p_scope_kind and d.site_id is not distinct from p_site_id
   and d.org_unit_id is not distinct from p_org_unit_id and d.task_kind is not distinct from p_task_kind
   and d.task_id is not distinct from p_task_id and d.status='active';
 insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,org_unit_id,
   task_kind,task_id,can_read,can_write,exception_kind,status,granted_by,ends_at,reason)
 values(p_tenant_id,p_membership_id,p_permission_key,p_decision,p_scope_kind,p_site_id,p_org_unit_id,p_task_kind,p_task_id,
   case when p_decision='deny' then false else p_can_read end,case when p_decision='deny' then false else p_can_write end,
   p_exception_kind,'active',v_actor,p_ends_at,btrim(p_reason)) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_actor_membership,p_scope_kind,'iam.permission_decision.set','iam.member_permission_decisions',v_id,
   jsonb_build_object('target_membership_id',p_membership_id,'permission_key',p_permission_key,'decision',p_decision,'reason',btrim(p_reason)));
 return v_id;
end $$;

commit;
