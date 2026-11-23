begin;
create or replace function private.phase1_permission_allowed(p_tenant_id uuid,p_permission_key text,p_site_id uuid default null,
 p_org_unit_id uuid default null,p_write boolean default false,p_task_kind text default null,p_task_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 with actor as (
   select m.id,m.member_role from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and private.has_module_entitlement(p_tenant_id,(select module_key from iam.permission_catalog where permission_key=p_permission_key))
 ), catalog as (
   select pc.permission_key,pc.enabled,pc.feature_key from iam.permission_catalog pc
    where pc.permission_key=p_permission_key 
 ), grants as (
   select rp.scope_kind,null::uuid site_id,null::uuid org_unit_id,mr.id assignment_id,null::text task_kind,null::uuid task_id
   from actor a join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.active
   join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.role_id=mr.role_id and rv.status='published'
   join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=p_permission_key
   where r.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and rv.role_family=r.role_family and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select pp.scope_kind,pp.site_id,pp.org_unit_id,null::uuid,null::text,null::uuid
   from actor a join iam.membership_permission_profiles mp on mp.tenant_id=p_tenant_id and mp.membership_id=a.id and mp.is_current
   join iam.permission_profiles p on p.tenant_id=mp.tenant_id and p.id=mp.profile_id and p.active and p.role_family=mp.role_family
   join iam.permission_profile_versions pv on pv.tenant_id=mp.tenant_id and pv.id=mp.profile_version_id and pv.profile_id=p.id
   join iam.permission_profile_permissions pp on pp.tenant_id=p.tenant_id and pp.profile_version_id=pv.id and pp.permission_key=p_permission_key
   where mp.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and (case when p_write then pp.can_write else pp.can_read or pp.can_write end)
   union all
   select d.scope_kind,d.site_id,d.org_unit_id,null::uuid,d.task_kind,d.task_id
   from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='allow' and d.status='active'
     and private.decision_source_valid(d.source_delegation_id,d.tenant_id) and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (case when p_write then d.can_write else d.can_read or d.can_write end)
 ), denies as (
   select d.* from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
     and private.decision_source_valid(d.source_delegation_id,d.tenant_id) and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (d.scope_kind='tenant' or (d.scope_kind='site' and d.site_id=p_site_id)
       or (d.scope_kind='org_unit' and d.org_unit_id=p_org_unit_id)
       or (d.scope_kind='assigned_task' and d.task_kind=p_task_kind and d.task_id=p_task_id))
 )
 select coalesce((select c.enabled and exists(select 1 from actor)
   and (c.feature_key is null or private.has_feature_entitlement(p_tenant_id,(select id from actor),c.feature_key))
   and private.people_scope_allowed(p_tenant_id,(select id from actor),p_site_id,p_org_unit_id)
   and (((select member_role='company_superadmin' from actor)
       and not exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id
         and l.membership_id=(select id from actor) and l.capability_key=p_permission_key and l.can_use=false))
     or ((select member_role<>'company_superadmin' from actor) and exists(select 1 from grants g where g.scope_kind='tenant'
       or (g.scope_kind='site' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_sites rs
          where rs.tenant_id=p_tenant_id and rs.membership_role_id=g.assignment_id and rs.site_id=p_site_id
            and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
         or (g.assignment_id is null and g.site_id=p_site_id)))
       or (g.scope_kind='org_unit' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_org_units ro
          where ro.tenant_id=p_tenant_id and ro.membership_role_id=g.assignment_id and ro.org_unit_id=p_org_unit_id
            and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
         or (g.assignment_id is null and g.org_unit_id=p_org_unit_id)))
       or (g.scope_kind='assigned_task' and (g.assignment_id is not null or (g.task_kind=p_task_kind and g.task_id=p_task_id)) and p_task_id is not null and exists(select 1 from iam.task_assignments ta
          where ta.tenant_id=p_tenant_id and ta.membership_id=(select id from actor) and ta.task_kind=p_task_kind
            and ta.task_id=p_task_id and ta.active and (ta.site_id is null or ta.site_id=p_site_id)
            and (ta.org_unit_id is null or ta.org_unit_id=p_org_unit_id))))))
   and not exists(select 1 from denies d where not exists(
     select 1 from actor a join iam.member_permission_decisions o on o.tenant_id=p_tenant_id and o.membership_id=a.id
     where o.permission_key=p_permission_key and o.decision='allow' and o.exception_kind='specific_override'
       and o.status='active' and o.starts_at<=now() and (o.ends_at is null or now()<o.ends_at)
       and (case when p_write then o.can_write else o.can_read or o.can_write end)
       and private.decision_source_valid(o.source_delegation_id,o.tenant_id)
       and d.scope_kind='tenant' and o.scope_kind in ('site','org_unit','assigned_task')
       and (o.scope_kind<>'site' or o.site_id=p_site_id)
       and (o.scope_kind<>'org_unit' or o.org_unit_id=p_org_unit_id)
       and (o.scope_kind<>'assigned_task' or (o.task_kind=p_task_kind and o.task_id=p_task_id))

   )) from catalog c),false)
$$;


-- A personal feature exception is non-delegable unless explicitly permitted.
create or replace function private.personal_feature_delegable(p_tenant uuid,p_membership uuid,p_permission text)
returns boolean language sql stable security definer set search_path='' as $$
 select not exists(select 1 from iam.permission_catalog c join core.entitlement_grants g
  on g.feature_key=c.feature_key and g.tenant_id=p_tenant and g.membership_id=p_membership
  where c.permission_key=p_permission and g.status='active' and g.revoked_at is null and g.starts_at<=now() and now()<g.expires_at)
 or exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant and l.membership_id=p_membership
  and l.capability_key=p_permission and l.can_use and l.can_delegate)
$$;
create or replace function private.assert_permission_grantable(p_tenant uuid,p_permission text,p_write boolean,p_site uuid,p_org uuid,
 p_task_kind text default null,p_task uuid default null) returns void
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 select * into m from iam.memberships where tenant_id=p_tenant and user_id=private.request_actor_id() and status='active';
 if m.id is null or not private.phase1_permission_allowed(p_tenant,p_permission,p_site,p_org,p_write,p_task_kind,p_task)
  or not private.personal_feature_delegable(p_tenant,m.id,p_permission)
  or exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant and l.membership_id=m.id
   and l.capability_key=p_permission and (not l.can_use or not l.can_delegate)) then
  raise exception 'permission_outside_grantor_authority' using errcode='42501';
 end if;
end $$;
create or replace function private.assert_action_delegable(p_tenant uuid,p_permission text,p_action text,p_site uuid,p_org uuid)
returns void language plpgsql security definer set search_path='' as $$
declare v_membership uuid;
begin
 select id into v_membership from iam.memberships where tenant_id=p_tenant and user_id=private.request_actor_id() and status='active';
 if v_membership is null or not api.authorize(p_tenant,p_permission,p_action,p_site,p_org)
  or not private.personal_feature_delegable(p_tenant,v_membership,p_permission)
  or exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant and l.membership_id=v_membership
   and l.capability_key=p_permission and (not l.can_use or not l.can_delegate)) then
  raise exception 'named_action_outside_delegable_authority' using errcode='42501'; end if;
end $$;
revoke all on function private.personal_feature_delegable(uuid,uuid,text) from public,anon,authenticated,service_role;
commit;
