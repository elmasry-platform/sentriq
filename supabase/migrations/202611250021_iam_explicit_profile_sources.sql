begin;
create or replace function api.set_default_permission_profile(
 p_tenant_id uuid,p_role_family text,p_profile_name text,p_permissions jsonb,
 p_target_mode text,p_target_membership_ids uuid[],p_reason text,p_source_delegation_id uuid
) returns table(profile_id uuid,profile_version_id uuid,default_updated boolean)
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=private.request_actor_id(); v_actor_membership uuid; v_profile uuid; v_version uuid;
        v_version_no integer; v_ids uuid[]:=coalesce(p_target_membership_ids,array[]::uuid[]);
        v_source uuid:=p_source_delegation_id; v_default boolean:=p_target_mode in ('new_users_only','selected_existing_and_new_users');
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
 if (select member_role from iam.memberships where id=v_actor_membership)<>'company_superadmin' then
  if v_source is null or not exists(select 1 from iam.delegation_envelopes d
   where d.tenant_id=p_tenant_id and d.id=v_source and d.delegate_membership_id=v_actor_membership
    and private.decision_source_valid(d.id,d.tenant_id) and 'role_assignment'=any(d.allowed_capabilities)
    and d.level in ('tenant','employees_default') and (d.level<>'employees_default' or p_role_family='employee')) then
   raise exception 'explicit_profile_source_required' using errcode='42501';end if;
 elsif v_source is not null then raise exception 'superadmin_profile_source_must_be_null' using errcode='23514';end if;
 insert into iam.permission_profiles(tenant_id,role_family,profile_name,created_by)
  values(p_tenant_id,p_role_family,btrim(p_profile_name),v_actor)
  on conflict(tenant_id,role_family) do update set profile_name=excluded.profile_name
  returning id into v_profile;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-profile-version:'||p_tenant_id::text||':'||v_profile::text,0));
 select coalesce(max(pv.version_no),0)+1 into v_version_no from iam.permission_profile_versions pv
  where pv.tenant_id=p_tenant_id and pv.profile_id=v_profile;
 insert into iam.permission_profile_versions(tenant_id,profile_id,version_no,created_by,sealed)
  values(p_tenant_id,v_profile,v_version_no,v_actor,false) returning id into v_version;
 insert into iam.permission_profile_permissions(tenant_id,profile_version_id,permission_key,scope_kind,site_id,org_unit_id,can_read,can_write,actions)
  select p_tenant_id,v_version,x.permission_key,x.scope_kind,x.site_id,x.org_unit_id,coalesce(x.can_read,false),coalesce(x.can_write,false),coalesce(x.actions,array_remove(array[case when x.can_read then 'read' end,case when x.can_write then 'write' end],null))
  from jsonb_to_recordset(p_permissions) as x(
    permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean,actions text[]);
 if v_default then
   insert into iam.permission_profile_defaults(tenant_id,role_family,profile_id,profile_version_id,updated_by,source_delegation_id)
    values(p_tenant_id,p_role_family,v_profile,v_version,v_actor,v_source)
    on conflict(tenant_id,role_family) do update set profile_id=excluded.profile_id,
      profile_version_id=excluded.profile_version_id,source_delegation_id=excluded.source_delegation_id,updated_by=excluded.updated_by,updated_at=now();
 end if;
 insert into iam.permission_profile_applications(tenant_id,profile_id,profile_version_id,target_mode,target_membership_ids,applied_by)
  values(p_tenant_id,v_profile,v_version,p_target_mode,v_ids,v_actor);
 if p_target_mode<>'new_users_only' then
   update iam.membership_permission_profiles set is_current=false
    where tenant_id=p_tenant_id and role_family=p_role_family and membership_id=any(v_ids) and is_current;
   insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,source,assigned_by,is_current,source_delegation_id)
    select p_tenant_id,m.id,p_role_family,v_profile,v_version,'explicit_application',v_actor,true,v_source
     from iam.memberships m where m.tenant_id=p_tenant_id and m.id=any(v_ids);
 end if;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_actor_membership,'tenant','iam.permission_profile.applied','iam.permission_profiles',v_profile,
   jsonb_build_object('role_family',p_role_family,'version_id',v_version,'target_mode',p_target_mode,'target_count',cardinality(v_ids),'reason',btrim(p_reason)));
 return query select v_profile,v_version,v_default;
end $$;


create or replace function api.set_default_permission_profile(
 p_tenant_id uuid,p_role_family text,p_profile_name text,p_permissions jsonb,
 p_target_mode text,p_target_membership_ids uuid[],p_reason text
) returns table(profile_id uuid,profile_version_id uuid,default_updated boolean)
language plpgsql security definer set search_path='' as $$
declare v_source uuid;v_count integer;
begin
 if not exists(select 1 from iam.memberships where tenant_id=p_tenant_id and user_id=private.request_actor_id()
  and status='active' and member_role='company_superadmin') then
  select count(*),min(d.id::text)::uuid into v_count,v_source from iam.delegation_envelopes d
   join iam.memberships m on m.id=d.delegate_membership_id and m.tenant_id=d.tenant_id
   where d.tenant_id=p_tenant_id and m.user_id=private.request_actor_id() and m.status='active'
    and private.decision_source_valid(d.id,d.tenant_id) and 'role_assignment'=any(d.allowed_capabilities)
    and d.level in ('tenant','employees_default') and (d.level<>'employees_default' or p_role_family='employee');
  if v_count<>1 then raise exception 'explicit_profile_source_required' using errcode='42501';end if;
 end if;
 return query select * from api.set_default_permission_profile(p_tenant_id,p_role_family,p_profile_name,p_permissions,
  p_target_mode,p_target_membership_ids,p_reason,v_source);
end $$;
create or replace function private.capture_default_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 if session_user='postgres' and current_setting('role')='none' then return new;end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=private.request_actor_id() and status='active';
 if not found then raise exception 'profile_default_actor_required' using errcode='42501';end if;
 if m.member_role='company_superadmin' then
  if new.source_delegation_id is not null then raise exception 'superadmin_default_source_must_be_null' using errcode='23514';end if;
 else
  if new.role_family<>'employee' or new.source_delegation_id is null or not exists(
   select 1 from iam.delegation_envelopes d where d.id=new.source_delegation_id and d.tenant_id=new.tenant_id
    and d.delegate_membership_id=m.id and private.decision_source_valid(d.id,d.tenant_id)
    and 'role_assignment'=any(d.allowed_capabilities) and d.level in ('tenant','employees_default')) then
   raise exception 'explicit_default_source_required' using errcode='42501';end if;
 end if;
 return new;
end $$;
create or replace function private.capture_assignment_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;v_explicit iam.delegation_envelopes%rowtype;
begin
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id then raise exception 'assignment_source_is_immutable' using errcode='23514';end if;
  return new;
 end if;
 if new.source_delegation_id is not null then
  select * into v_explicit from iam.delegation_envelopes where tenant_id=new.tenant_id and id=new.source_delegation_id;
  if (current_setting('role')<>'service_role' and not exists(select 1 from iam.memberships actor where actor.id=v_explicit.delegate_membership_id and actor.tenant_id=new.tenant_id and actor.user_id=private.request_actor_id() and actor.status='active')) or not private.decision_source_valid(v_explicit.id,v_explicit.tenant_id) or (tg_table_name='membership_permission_profiles' and v_explicit.level not in ('tenant','employees_default')) or not 'role_assignment'=any(v_explicit.allowed_capabilities)
   or not exists(select 1 from iam.memberships t where t.tenant_id=new.tenant_id and t.id=new.membership_id
    and (v_explicit.level<>'employees_default' or t.member_role='employee')) then
   raise exception 'explicit_assignment_source_invalid' using errcode='42501';end if;
  return new;
 end if;
 if session_user='postgres' and current_setting('role')='none' then return new;end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=private.request_actor_id() and status='active';
 if not found then raise exception 'assignment_actor_required' using errcode='42501';end if;
 if m.member_role<>'company_superadmin' then
  raise exception 'explicit_assignment_source_required' using errcode='42501';
 end if;
 return new;
end $$;

revoke all on function api.set_default_permission_profile(uuid,text,text,jsonb,text,uuid[],text,uuid) from public,anon,service_role;
grant execute on function api.set_default_permission_profile(uuid,text,text,jsonb,text,uuid[],text,uuid) to authenticated;
commit;
