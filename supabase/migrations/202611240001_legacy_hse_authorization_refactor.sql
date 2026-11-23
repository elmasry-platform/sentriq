-- Route legacy HSE rows, API checks, triggers, audit, and Storage through the
-- Phase 1 permission evaluator. Only immutable seeded global Employee roles
-- retain a bounded compatibility path; unclassified custom roles fail closed.
begin;

-- The nine seeded global HSE roles are protected catalog roles, not tenant
-- roles. Their operational role family is deterministic and remains Employee.
drop trigger if exists role_family_guard on iam.roles;
update iam.roles
 set role_family='employee'
 where tenant_id is null and protected
   and role_key in ('inspector','reviewer_1','reviewer_2','final_reviewer','action_owner',
                    'closure_reviewer','form_designer','auditor','safety_officer')
   and role_family is distinct from 'employee';
create trigger role_family_guard before insert or update of role_family,tenant_id on iam.roles
 for each row execute function private.guard_role_family_change();

do $$ begin
 if not exists(select 1 from pg_constraint where conrelid='iam.roles'::regclass and conname='roles_global_hse_family_check') then
   alter table iam.roles add constraint roles_global_hse_family_check
     check(tenant_id is not null or (protected and role_family='employee')) not valid;
 end if;
end $$;
alter table iam.roles validate constraint roles_global_hse_family_check;

-- Preserve evidence of any historic assignment that does not match the
-- classified global role family. It remains in history but will not authorize.
insert into iam.phase1_role_family_review(tenant_id,role_id,role_key,reason,
 observed_admin_assignments,observed_employee_assignments)
select mr.tenant_id,r.id,r.role_key,'Global protected Employee role assigned to a non-Employee management family; access fails closed',
 count(*) filter(where m.member_role<>'employee'),count(*) filter(where m.member_role='employee')
from iam.membership_roles mr join iam.roles r on r.id=mr.role_id and r.tenant_id is null and r.protected
join iam.memberships m on m.tenant_id=mr.tenant_id and m.id=mr.membership_id
where r.role_family='employee' and m.member_role<>'employee'
group by mr.tenant_id,r.id,r.role_key
on conflict(tenant_id,role_id) do update set reason=excluded.reason,
 observed_admin_assignments=excluded.observed_admin_assignments,
 observed_employee_assignments=excluded.observed_employee_assignments;

create or replace function private.validate_membership_role() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_role iam.roles%rowtype; v_membership iam.memberships%rowtype; v_version iam.role_versions%rowtype;
begin
 select * into v_role from iam.roles where id=new.role_id for key share;
 select * into v_membership from iam.memberships where tenant_id=new.tenant_id and id=new.membership_id for key share;
 if v_role.id is null or v_membership.id is null or (v_role.tenant_id is not null and v_role.tenant_id<>new.tenant_id) then
   raise exception 'functional role must belong to the same tenant' using errcode='23503';
 end if;
 if v_role.role_family is null or v_role.role_family not in ('admin','employee') then
   raise exception 'functional role family requires owner classification' using errcode='23514';
 end if;
 if v_role.role_family<>(case when v_membership.member_role='employee' then 'employee' else 'admin' end) then
   raise exception 'functional role family does not match membership family' using errcode='23514';
 end if;
 if v_role.tenant_id is not null then
   if new.role_version_id is null then raise exception 'published role version required' using errcode='23514'; end if;
   select * into v_version from iam.role_versions where tenant_id=new.tenant_id and id=new.role_version_id
     and role_id=new.role_id and status='published';
   if not found or v_version.role_family<>v_role.role_family then
     raise exception 'published role version must match role and family' using errcode='23514';
   end if;
 elsif not v_role.protected or new.role_version_id is not null then
   raise exception 'only classified protected global roles may omit tenant role versions' using errcode='23514';
 end if;
 return new;
end $$;
drop trigger if exists membership_role_tenant_guard on iam.membership_roles;
create trigger membership_role_tenant_guard before insert or update of tenant_id,membership_id,role_id,role_version_id
 on iam.membership_roles for each row execute function private.validate_membership_role();

-- Bounded compatibility for protected, immutable global HSE role seeds. This
-- never reads tenant role_permissions and never overrides an explicit deny.
create or replace function private.legacy_global_hse_permission_allowed(
 p_tenant_id uuid,p_permission_key text,p_site_id uuid,p_write boolean,p_task_kind text,p_task_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 with actor as (
   select m.id from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.member_role='employee'
     and m.status='active' and t.status='active' and private.has_module_entitlement(p_tenant_id,'hse')
 ), catalog as (
   select pc.feature_key from iam.permission_catalog pc
   where pc.permission_key=p_permission_key and pc.module_key='hse' and pc.enabled
 ), target as (
   select s.org_unit_id from core.sites s where s.tenant_id=p_tenant_id and s.id=p_site_id
 ), denied as (
   select exists(select 1 from actor a join iam.member_permission_decisions d
      on d.tenant_id=p_tenant_id and d.membership_id=a.id
    where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
      and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
      and (d.scope_kind='tenant'
        or (d.scope_kind='site' and d.site_id=p_site_id)
        or (d.scope_kind='org_unit' and d.org_unit_id=(select org_unit_id from target))
        or (d.scope_kind='assigned_task' and d.task_kind=p_task_kind and d.task_id=p_task_id))) as value
 )
 select coalesce(exists(
   select 1 from actor a cross join catalog c
   where c.feature_key is null or private.has_feature_entitlement(p_tenant_id,a.id,c.feature_key)
 ),false) and coalesce(exists(
   select 1 from actor a cross join catalog c
   join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.tenant_id is null and r.protected
      and r.role_family='employee' and r.active
   join iam.role_permissions rp on rp.role_id=r.id and rp.permission_key=p_permission_key and rp.active
   where mr.role_version_id is null and mr.revoked_at is null and mr.starts_at<=now()
     and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
     and (p_site_id is null or exists(select 1 from iam.site_access sa where sa.tenant_id=p_tenant_id
       and sa.membership_id=a.id and sa.site_id=p_site_id and sa.active))
     and (rp.scope_kind='tenant'
       or (rp.scope_kind='site' and exists(select 1 from iam.membership_role_sites rs
         where rs.tenant_id=p_tenant_id and rs.membership_role_id=mr.id and rs.site_id=p_site_id
           and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
       or (rp.scope_kind='org_unit' and (select org_unit_id from target) is not null
         and exists(select 1 from iam.org_unit_access oa where oa.tenant_id=p_tenant_id
           and oa.membership_id=a.id and oa.org_unit_id=(select org_unit_id from target) and oa.active)
         and exists(select 1 from iam.membership_role_org_units ro where ro.tenant_id=p_tenant_id
           and ro.membership_role_id=mr.id and ro.org_unit_id=(select org_unit_id from target)
           and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
       or (rp.scope_kind='assigned_task' and p_task_id is not null and exists(select 1
         from iam.task_assignments ta where ta.tenant_id=p_tenant_id and ta.membership_id=a.id
           and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active
           and ta.site_id=p_site_id and (ta.org_unit_id is null or ta.org_unit_id=(select org_unit_id from target)))))
     and not (select value from denied)
 ),false)
$$;

create or replace function private.can_access_hse(
 p_tenant_id uuid,p_permission text,p_site_id uuid default null,p_write boolean default false,
 p_task_kind text default null,p_task_id uuid default null
) returns boolean language sql stable security definer set search_path='' as $$
 select private.phase1_permission_allowed(p_tenant_id,p_permission,p_site_id,
          (select s.org_unit_id from core.sites s where s.tenant_id=p_tenant_id and s.id=p_site_id),
          p_write,p_task_kind,p_task_id)
     or private.legacy_global_hse_permission_allowed(p_tenant_id,p_permission,p_site_id,p_write,p_task_kind,p_task_id)
$$;

create or replace function private.can_access_core(p_tenant_id uuid,p_permission text,p_site_id uuid default null,p_write boolean default false)
returns boolean language sql stable security definer set search_path='' as $$
 select p_permission='core.structure.manage' and private.phase1_permission_allowed(
   p_tenant_id,'scope_assign',p_site_id,
   (select s.org_unit_id from core.sites s where s.tenant_id=p_tenant_id and s.id=p_site_id),p_write)
$$;

create or replace function api.can_use_feature(p_tenant_id uuid,p_feature_key text,p_permission text,p_site_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
     and private.has_feature_entitlement(m.tenant_id,m.id,p_feature_key)
     and (private.phase1_permission_allowed(p_tenant_id,p_permission,p_site_id,
          (select s.org_unit_id from core.sites s where s.tenant_id=p_tenant_id and s.id=p_site_id),false)
       or private.legacy_global_hse_permission_allowed(p_tenant_id,p_permission,p_site_id,false,null,null)))
$$;

-- Remove Platform Operator identity from company records and audit surfaces.
drop policy if exists audit_read on audit.events;
create policy audit_read on audit.events for select to authenticated
 using(tenant_id is not null and private.phase1_permission_allowed(tenant_id,'hse.audit.read',null,null,false));

drop policy if exists membership_read on iam.memberships;
create policy membership_read on iam.memberships for select to authenticated
 using(user_id=auth.uid() or private.can_manage_tenant(tenant_id));

drop policy if exists roles_read on iam.roles;
create policy roles_read on iam.roles for select to authenticated
 using(tenant_id is null or private.phase1_membership(tenant_id) is not null);

drop policy if exists role_permissions_read on iam.role_permissions;
create policy role_permissions_read on iam.role_permissions for select to authenticated
 using(exists(select 1 from iam.roles r where r.id=role_id
   and (r.tenant_id is null or private.phase1_membership(r.tenant_id) is not null)));

-- The Superadmin manager branch is capability-gated and deny-aware. Employees
-- retain ownership-bound inspection creation and normal workflow transitions.
create or replace function private.guard_inspection_insert() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status='draft' and (new.current_stage is not null or new.submitted_at is not null) then
   raise exception 'draft inspection has invalid workflow fields' using errcode='23514';
 elsif new.status='submitted' and (new.current_stage is distinct from 'reviewer_1' or new.submitted_at is null) then
   raise exception 'submitted inspection must enter reviewer_1' using errcode='23514';
 elsif new.status not in ('draft','submitted') then
   raise exception 'inspection must start as draft or submitted' using errcode='23514';
 end if;
 if new.revision<>1 then raise exception 'new inspection revision must be 1' using errcode='23514'; end if;
 if not private.can_access_hse(new.tenant_id,'hse.inspections.create',new.site_id,true)
   or (new.inspector_membership_id is distinct from private.current_membership_id(new.tenant_id)
       and not private.can_manage_tenant(new.tenant_id)) then
   raise exception 'inspection_create_not_allowed' using errcode='42501';
 end if;
 return new;
end $$;

create or replace function private.guard_inspection_update() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_is_inspector boolean; v_is_reviewer boolean; v_is_manager boolean;
begin
 v_is_manager:=exists(select 1 from iam.memberships m where m.tenant_id=old.tenant_id
   and m.user_id=auth.uid() and m.member_role='company_superadmin' and m.status='active')
   and private.can_access_hse(old.tenant_id,'hse.inspections.create',old.site_id,true);
 if v_is_manager then return new; end if;
 v_is_inspector:=old.inspector_membership_id=private.current_membership_id(old.tenant_id)
   and private.can_access_hse(old.tenant_id,'hse.inspections.create',old.site_id,true);
 v_is_reviewer:=old.current_stage is not null
   and (private.can_access_hse(old.tenant_id,'hse.inspections.review',old.site_id,true,'review',old.id)
     or private.can_access_hse(old.tenant_id,'hse.inspections.review.'||old.current_stage,old.site_id,true,'review',old.id));
 if v_is_inspector then
  if (to_jsonb(new)-array['answers','title','status','revision','updated_at']) is distinct from (to_jsonb(old)-array['answers','title','status','revision','updated_at'])
   or not ((old.status in ('draft','returned') and new.status='submitted') or new.status=old.status)
   or (old.status not in ('draft','returned') and (new.answers is distinct from old.answers or new.title is distinct from old.title))
   or (new.current_stage is distinct from old.current_stage and not(old.status in ('draft','returned') and new.status='submitted' and new.current_stage='reviewer_1'))
   or new.revision<>old.revision+1 then raise exception 'inspection fields or transition are restricted' using errcode='42501'; end if;
  if old.status in ('draft','returned') and new.status='submitted' then new.current_stage:='reviewer_1'; new.submitted_at:=now(); end if;
 elsif v_is_reviewer then
  if (to_jsonb(new)-array['status','current_stage','revision','updated_at']) is distinct from (to_jsonb(old)-array['status','current_stage','revision','updated_at']) then
    raise exception 'reviewers can only change workflow state' using errcode='42501'; end if;
  if new.revision<>old.revision+1 or not (
   (old.status='submitted' and old.current_stage='reviewer_1' and new.status='in_review' and new.current_stage='reviewer_2')
   or (old.status in ('submitted','in_review') and new.status='returned' and new.current_stage=old.current_stage)
   or (old.status='in_review' and ((old.current_stage='reviewer_2' and new.status='in_review' and new.current_stage='final_reviewer')
      or (old.current_stage='final_reviewer' and new.status='approved' and new.current_stage=old.current_stage)))) then
   raise exception 'invalid inspection workflow transition' using errcode='23514'; end if;
 else raise exception 'insufficient_privilege' using errcode='42501'; end if;
 return new;
end $$;

create or replace function private.guard_action_update() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_manage boolean; v_assigned boolean; v_closure boolean;
begin
  v_manage:=private.can_access_hse(old.tenant_id,'hse.actions.manage',old.site_id,true);
  if v_manage then return new; end if;
  v_closure:=private.can_access_hse(old.tenant_id,'hse.actions.close_review',old.site_id,true);
  v_assigned:=private.can_access_hse(old.tenant_id,'hse.actions.update_assigned',old.site_id,true,'action',old.id);
  if v_closure and old.status='closure_requested' and new.status in ('closed','in_progress') then
    if (to_jsonb(new)-array['status','revision','updated_at']) is distinct from (to_jsonb(old)-array['status','revision','updated_at']) then
      raise exception 'closure reviewers can only approve or return closure' using errcode='42501'; end if;
  elsif v_assigned then
    if (to_jsonb(new)-array['status','revision','updated_at']) is distinct from (to_jsonb(old)-array['status','revision','updated_at'])
      or not ((old.status='open' and new.status='in_progress')
        or (old.status='in_progress' and new.status='closure_requested')
        or (old.status='closure_requested' and new.status='in_progress') or new.status=old.status) then
      raise exception 'assigned action fields or transition are restricted' using errcode='42501';
    end if;
  else
    raise exception 'insufficient_privilege' using errcode='42501';
  end if;
  return new;
end $$;

drop policy if exists inspections_insert on hse.inspections;
create policy inspections_insert on hse.inspections for insert to authenticated with check (
  (private.can_manage_tenant(tenant_id) or inspector_membership_id=private.current_membership_id(tenant_id))
  and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true));
drop policy if exists inspections_update on hse.inspections;
create policy inspections_update on hse.inspections for update to authenticated
 using((private.can_manage_tenant(tenant_id) and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true))
   or (inspector_membership_id=private.current_membership_id(tenant_id)
     and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true)))
 with check((private.can_manage_tenant(tenant_id) and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true))
   or (inspector_membership_id=private.current_membership_id(tenant_id)
     and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true)));
drop policy if exists reviews_insert on hse.inspection_reviews;
create policy reviews_insert on hse.inspection_reviews for insert to authenticated with check (
 actor_user_id=auth.uid() and actor_membership_id=private.current_membership_id(tenant_id)
 and exists(select 1 from hse.inspections i where i.tenant_id=inspection_reviews.tenant_id
   and i.id=inspection_reviews.inspection_id and i.status in ('submitted','in_review')
   and i.current_stage=inspection_reviews.stage
   and (private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.review',i.site_id,true,'review',i.id)
     or private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.review.'||inspection_reviews.stage,i.site_id,true,'review',i.id))));

revoke all on function private.legacy_global_hse_permission_allowed(uuid,text,uuid,boolean,text,uuid) from public,anon,authenticated,service_role;
revoke all on function private.has_hse_permission(uuid,uuid,text,uuid,boolean,text,uuid) from public,anon,authenticated,service_role;

commit;
