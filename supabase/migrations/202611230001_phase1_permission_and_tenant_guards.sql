-- Phase 1 security remediation: remove platform tenant-write bypasses,
-- fail closed on unversioned role assignments, and bind exceptions to denies.
begin;

-- Platform authority is deliberately separate from company role management.
-- Platform operators cannot satisfy this company-only helper.
create or replace function private.can_manage_tenant(p_tenant_id uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(
   select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid()
     and m.member_role='company_superadmin' and m.status='active' and t.status='active'
 )
$$;

-- Tenant ownership cannot be reassigned in place, including structure rows.
create or replace function private.guard_tenant_id_immutable() returns trigger
language plpgsql set search_path='' as $$
begin
 if new.tenant_id is distinct from old.tenant_id then
   raise exception 'tenant_id_is_immutable' using errcode='23514';
 end if;
 return new;
end $$;
do $$
declare r record;
begin
 for r in select * from (values
   ('hse','people'),('hse','contractor_organizations'),('hse','person_engagements'),
   ('hse','person_engagement_events'),('core','sites'),('core','org_units')
 ) x(schema_name,table_name)
 loop
   execute format('drop trigger if exists phase1_tenant_id_immutable on %I.%I',r.schema_name,r.table_name);
   execute format('drop trigger if exists a_phase1_tenant_id_immutable on %I.%I',r.schema_name,r.table_name);
   execute format('create trigger a_phase1_tenant_id_immutable before update of tenant_id on %I.%I for each row execute function private.guard_tenant_id_immutable()',r.schema_name,r.table_name);
 end loop;
end $$;

-- Never fall back from a missing/invalid published role version to mutable
-- legacy role_permissions rows.
create or replace function private.phase1_permission_allowed(p_tenant_id uuid,p_permission_key text,p_site_id uuid default null,
 p_org_unit_id uuid default null,p_write boolean default false,p_task_kind text default null,p_task_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 with actor as (
   select m.id,m.member_role from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and private.has_module_entitlement(p_tenant_id,'hse')
 ), catalog as (
   select pc.permission_key,pc.enabled,pc.feature_key from iam.permission_catalog pc
    where pc.permission_key=p_permission_key and pc.module_key='hse'
 ), grants as (
   select rp.scope_kind,null::uuid site_id,null::uuid org_unit_id,mr.id assignment_id
   from actor a join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.active
   join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.role_id=mr.role_id and rv.status='published'
   join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=p_permission_key
   where r.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and rv.role_family=r.role_family and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select pp.scope_kind,pp.site_id,pp.org_unit_id,null::uuid
   from actor a join iam.membership_permission_profiles mp on mp.tenant_id=p_tenant_id and mp.membership_id=a.id and mp.is_current
   join iam.permission_profiles p on p.tenant_id=mp.tenant_id and p.id=mp.profile_id and p.active and p.role_family=mp.role_family
   join iam.permission_profile_versions pv on pv.tenant_id=mp.tenant_id and pv.id=mp.profile_version_id and pv.profile_id=p.id
   join iam.permission_profile_permissions pp on pp.tenant_id=p.tenant_id and pp.profile_version_id=pv.id and pp.permission_key=p_permission_key
   where mp.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and (case when p_write then pp.can_write else pp.can_read or pp.can_write end)
   union all
   select d.scope_kind,d.site_id,d.org_unit_id,null::uuid
   from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='allow' and d.status='active'
     and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (case when p_write then d.can_write else d.can_read or d.can_write end)
 ), denies as (
   select d.* from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
     and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
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
     or exists(select 1 from grants g where g.scope_kind='tenant'
       or (g.scope_kind='site' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_sites rs
          where rs.tenant_id=p_tenant_id and rs.membership_role_id=g.assignment_id and rs.site_id=p_site_id
            and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
         or (g.assignment_id is null and g.site_id=p_site_id)))
       or (g.scope_kind='org_unit' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_org_units ro
          where ro.tenant_id=p_tenant_id and ro.membership_role_id=g.assignment_id and ro.org_unit_id=p_org_unit_id
            and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
         or (g.assignment_id is null and g.org_unit_id=p_org_unit_id)))
       or (g.scope_kind='assigned_task' and p_task_id is not null and exists(select 1 from iam.task_assignments ta
          where ta.tenant_id=p_tenant_id and ta.membership_id=(select id from actor) and ta.task_kind=p_task_kind
            and ta.task_id=p_task_id and ta.active and (ta.site_id is null or ta.site_id=p_site_id)
            and (ta.org_unit_id is null or ta.org_unit_id=p_org_unit_id)))))
   and not exists(select 1 from denies d where not exists(
     select 1 from actor a join iam.member_permission_decisions o on o.tenant_id=p_tenant_id and o.membership_id=a.id
     where o.permission_key=p_permission_key and o.decision='allow' and o.exception_kind='specific_override'
       and o.status='active' and o.starts_at<=now() and (o.ends_at is null or now()<o.ends_at)
       and (case when p_write then o.can_write else o.can_read or o.can_write end)
       and private.phase1_can_manage(p_tenant_id,'permissions.specific_override',a.id,p_site_id,p_org_unit_id)
       and ((o.scope_kind=d.scope_kind and o.site_id is not distinct from d.site_id
          and o.org_unit_id is not distinct from d.org_unit_id and o.task_kind is not distinct from d.task_kind
          and o.task_id is not distinct from d.task_id)
         or (d.scope_kind='tenant' and o.scope_kind in ('site','org_unit','assigned_task')
           and (o.scope_kind<>'site' or o.site_id=p_site_id)
           and (o.scope_kind<>'org_unit' or o.org_unit_id=p_org_unit_id)
           and (o.scope_kind<>'assigned_task' or (o.task_kind=p_task_kind and o.task_id=p_task_id)))
       )
   )) from catalog c),false)
$$;

-- Enforce family at role creation/update and assignment. Historical unknown
-- roles remain unusable until owner classification; no NULL-version fallback.
do $$ begin
 if not exists(select 1 from pg_constraint where conrelid='iam.roles'::regclass and conname='roles_phase1_family_not_null_check') then
   alter table iam.roles add constraint roles_phase1_family_not_null_check
     check(tenant_id is null or (role_family is not null and role_family in ('admin','employee'))) not valid;
 end if;
end $$;
create or replace function private.validate_membership_role() returns trigger language plpgsql security definer set search_path='' as $$
declare v_role iam.roles%rowtype; v_membership iam.memberships%rowtype; v_version iam.role_versions%rowtype;
begin
 select * into v_role from iam.roles where id=new.role_id for key share;
 select * into v_membership from iam.memberships where tenant_id=new.tenant_id and id=new.membership_id for key share;
 if v_role.id is null or v_membership.id is null or (v_role.tenant_id is not null and v_role.tenant_id<>new.tenant_id) then
   raise exception 'functional role must belong to the same tenant' using errcode='23503';
 end if;
 if v_role.tenant_id is not null and (v_role.role_family is null or v_role.role_family not in ('admin','employee')) then
   raise exception 'functional role family requires owner classification' using errcode='23514';
 end if;
 if v_role.tenant_id is not null and v_role.role_family<>(case when v_membership.member_role='employee' then 'employee' else 'admin' end) then
   raise exception 'functional role family does not match membership family' using errcode='23514';
 end if;
 if v_role.tenant_id is not null then
   if new.role_version_id is null then raise exception 'published role version required' using errcode='23514'; end if;
   select * into v_version from iam.role_versions where tenant_id=new.tenant_id and id=new.role_version_id
     and role_id=new.role_id and status='published';
   if not found or v_version.role_family<>v_role.role_family then
     raise exception 'published role version must match role and family' using errcode='23514';
   end if;
 elsif new.role_version_id is not null then
   raise exception 'global protected roles do not accept tenant role versions' using errcode='23514';
 end if;
 return new;
end $$;
drop trigger if exists membership_role_tenant_guard on iam.membership_roles;
create trigger membership_role_tenant_guard before insert or update of tenant_id,membership_id,role_id,role_version_id
 on iam.membership_roles for each row execute function private.validate_membership_role();

create or replace function private.guard_role_family_change() returns trigger language plpgsql security definer set search_path='' as $$
begin
 if new.tenant_id is not null and (new.role_family is null or new.role_family not in ('admin','employee')) then
   raise exception 'tenant role requires Admin or Employee family' using errcode='23514';
 end if;
 if new.role_family is distinct from old.role_family and (
   exists(select 1 from iam.membership_roles mr where mr.tenant_id=old.tenant_id and mr.role_id=old.id)
   or exists(select 1 from iam.role_versions rv where rv.tenant_id=old.tenant_id and rv.role_id=old.id)
 ) then raise exception 'role family is immutable after version or assignment history exists' using errcode='23514'; end if;
 return new;
end $$;
drop trigger if exists role_family_guard on iam.roles;
create trigger role_family_guard before insert or update of role_family,tenant_id on iam.roles
 for each row execute function private.guard_role_family_change();

revoke all on function private.guard_tenant_id_immutable(),private.guard_role_family_change() from public,anon,authenticated,service_role;
revoke all on function private.phase1_permission_allowed(uuid,text,uuid,uuid,boolean,text,uuid) from public,anon,service_role;
grant execute on function private.phase1_permission_allowed(uuid,text,uuid,uuid,boolean,text,uuid) to authenticated,service_role;

commit;
