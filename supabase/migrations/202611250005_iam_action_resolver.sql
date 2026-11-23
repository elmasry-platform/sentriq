begin;
create or replace function api.authorize(p_tenant_id uuid,p_permission_key text,p_action text,
 p_site_id uuid default null,p_org_unit_id uuid default null,p_task_kind text default null,p_task_id uuid default null)
returns boolean language plpgsql stable security definer set search_path='' as $$
declare m iam.memberships%rowtype; c iam.permission_catalog%rowtype; v_allowed boolean;
begin
 select * into m from iam.memberships where tenant_id=p_tenant_id and user_id=private.request_actor_id() and status='active';
 select * into c from iam.permission_catalog where permission_key=p_permission_key and enabled;
 if m.id is null or c.permission_key is null or not p_action=any(c.supported_actions)
  or not exists(select 1 from core.tenants where id=p_tenant_id and status='active')
  or not private.has_module_entitlement(p_tenant_id,c.module_key)
  or (c.feature_key is not null and not private.has_feature_entitlement(p_tenant_id,m.id,c.feature_key))
  or not private.people_scope_allowed(p_tenant_id,m.id,p_site_id,p_org_unit_id)
  or (p_site_id is not null and not exists(select 1 from core.sites where tenant_id=p_tenant_id and id=p_site_id
    and (p_org_unit_id is null or org_unit_id=p_org_unit_id)))
  or (p_task_id is not null and not exists(select 1 from iam.task_assignments where tenant_id=p_tenant_id
    and membership_id=m.id and task_kind=p_task_kind and task_id=p_task_id and active
    and (site_id is null or site_id=p_site_id) and (org_unit_id is null or org_unit_id=p_org_unit_id))) then return false; end if;
 -- Legacy read/write grants retain only their original explicit meaning.
 if p_action in ('read','write') then
  return private.phase1_permission_allowed(p_tenant_id,p_permission_key,p_site_id,p_org_unit_id,p_action='write',p_task_kind,p_task_id);
 end if;
 if exists(select 1 from iam.member_permission_decisions d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)) then return false; end if;
 if exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)) then return false; end if;
 if m.member_role='company_superadmin' then
  return not exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id
    and l.membership_id=m.id and l.capability_key=p_permission_key and not l.can_use);
 end if;
 return private.functional_action_allowed(p_tenant_id,m.id,p_permission_key,p_action,p_site_id,p_org_unit_id,p_task_kind,p_task_id) or exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='allow' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id));
end $$;

create or replace function api.publish_role_version(p_tenant_id uuid,p_role_id uuid,p_permissions jsonb,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_version uuid; v_no integer; r iam.roles%rowtype; p record;
begin
 if not private.phase1_can_manage(p_tenant_id,'role_assignment') or p_reason is null
  or length(btrim(p_reason)) not between 3 and 500 or jsonb_typeof(p_permissions)<>'array'
  or jsonb_array_length(p_permissions) not between 1 and 100 then
  raise exception 'role_publication_not_authorized' using errcode='42501'; end if;
 select * into r from iam.roles where tenant_id=p_tenant_id and id=p_role_id and active for update;
 if not found or r.role_family is null then raise exception 'active_tenant_role_required' using errcode='23514'; end if;
 select coalesce(max(version_no),0)+1 into v_no from iam.role_versions where tenant_id=p_tenant_id and role_id=p_role_id;
 insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by)
 values(p_tenant_id,p_role_id,v_no,r.role_family,'draft',private.request_actor_id()) returning id into v_version;
 for p in select * from jsonb_to_recordset(p_permissions) as x(permission_key text,scope_kind text,can_read boolean,can_write boolean,actions text[]) loop
  if p.scope_kind not in ('tenant','site','org_unit') or p.can_read is null or p.can_write is null or not(p.can_read or p.can_write or cardinality(coalesce(p.actions,'{}'))>0)
   or not exists(select 1 from iam.permission_catalog c where c.permission_key=p.permission_key and c.enabled and p.scope_kind=any(c.supported_scope_kinds)) then
   raise exception 'invalid_role_permission' using errcode='22023'; end if;
  -- Scoped grants are revalidated against the actual binding on assignment.
  if p.scope_kind='tenant' and (p.can_read or p.can_write) then perform private.assert_permission_grantable(p_tenant_id,p.permission_key,p.can_write,null,null); end if;
  insert into iam.role_version_permissions(tenant_id,role_version_id,permission_key,scope_kind,can_read,can_write,actions)
  values(p_tenant_id,v_version,p.permission_key,p.scope_kind,p.can_read,p.can_write,coalesce(p.actions,array_remove(array[case when p.can_read then 'read' end,case when p.can_write then 'write' end],null)));
 end loop;
 update iam.role_versions set status='published',published_at=now() where tenant_id=p_tenant_id and id=v_version;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.role_version.published','iam.role_versions',v_version,
  jsonb_build_object('role_id',p_role_id,'version_no',v_no,'reason',btrim(p_reason)));
 return v_version;
end $$;

commit;
