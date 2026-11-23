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
     and rv.role_family=r.role_family and private.decision_source_valid(mr.source_delegation_id,mr.tenant_id) and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select pp.scope_kind,pp.site_id,pp.org_unit_id,null::uuid,null::text,null::uuid
   from actor a join iam.membership_permission_profiles mp on mp.tenant_id=p_tenant_id and mp.membership_id=a.id and mp.is_current and private.decision_source_valid(mp.source_delegation_id,mp.tenant_id)
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


create or replace function private.functional_action_allowed(p_tenant uuid,p_membership uuid,p_permission text,p_action text,
 p_site uuid,p_org uuid,p_task_kind text,p_task uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(
  select 1 from iam.membership_roles mr
   join iam.memberships m on m.tenant_id=mr.tenant_id and m.id=mr.membership_id and m.status='active'
   join iam.roles r on r.id=mr.role_id and r.tenant_id=mr.tenant_id and r.active
   join iam.role_versions v on v.tenant_id=mr.tenant_id and v.id=mr.role_version_id and v.role_id=r.id and v.status='published'
   join iam.role_version_permissions p on p.tenant_id=mr.tenant_id and p.role_version_id=v.id and p.permission_key=p_permission
  where mr.tenant_id=p_tenant and mr.membership_id=p_membership
   and m.member_role in ('company_admin','employee') and r.role_family=case when m.member_role='employee' then 'employee' else 'admin' end
   and v.role_family=r.role_family and p_action=any(p.actions) and private.decision_source_valid(mr.source_delegation_id,mr.tenant_id) and mr.revoked_at is null
   and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
   and (p.scope_kind='tenant'
    or (p.scope_kind='site' and exists(select 1 from iam.membership_role_sites b where b.tenant_id=mr.tenant_id
      and b.membership_role_id=mr.id and b.site_id=p_site and b.revoked_at is null and b.granted_at<=now() and (b.ends_at is null or now()<b.ends_at)))
    or (p.scope_kind='org_unit' and exists(select 1 from iam.membership_role_org_units b where b.tenant_id=mr.tenant_id
      and b.membership_role_id=mr.id and b.org_unit_id=p_org and b.revoked_at is null and b.granted_at<=now() and (b.ends_at is null or now()<b.ends_at))))
 ) or exists(
  select 1 from iam.membership_permission_profiles mp
   join iam.memberships m on m.tenant_id=mp.tenant_id and m.id=mp.membership_id and m.status='active'
   join iam.permission_profiles pr on pr.tenant_id=mp.tenant_id and pr.id=mp.profile_id and pr.active
   join iam.permission_profile_versions v on v.tenant_id=mp.tenant_id and v.id=mp.profile_version_id and v.profile_id=pr.id
   join iam.permission_profile_permissions p on p.tenant_id=mp.tenant_id and p.profile_version_id=v.id and p.permission_key=p_permission
  where mp.tenant_id=p_tenant and mp.membership_id=p_membership and mp.is_current and private.decision_source_valid(mp.source_delegation_id,mp.tenant_id)
   and m.member_role in ('company_admin','employee') and mp.role_family=case when m.member_role='employee' then 'employee' else 'admin' end
   and pr.role_family=mp.role_family and p_action=any(p.actions)
   and private.scope_matches(p.scope_kind,p.site_id,p.org_unit_id,null,null,p_site,p_org,p_task_kind,p_task)
 )
$$;

commit;
