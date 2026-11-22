-- Classify legacy tenant roles from membership management levels before Phase 1
-- role versions are materialized. Mixed roles are split by management family.
-- Ambiguous or unassigned roles remain unclassified and are recorded for review.
begin;

alter table iam.roles add column if not exists role_family text;
create table if not exists iam.phase1_role_family_review (
 tenant_id uuid not null references core.tenants(id) on delete restrict,
 role_id uuid not null references iam.roles(id) on delete restrict,
 role_key text not null,
 reason text not null,
 observed_admin_assignments integer not null default 0,
 observed_employee_assignments integer not null default 0,
 recorded_at timestamptz not null default now(),
 resolved_at timestamptz,
 resolved_by uuid references auth.users(id) on delete restrict,
 primary key(tenant_id,role_id),
 check((resolved_at is null)=(resolved_by is null))
);

do $$
declare r record; v_admin integer; v_employee integer; v_clone_id uuid; v_clone_key text; a record; v_new_assignment uuid;
begin
 for r in select id,tenant_id,role_key,label,created_by from iam.roles
   where tenant_id is not null and role_family is null order by tenant_id,role_key
 loop
   -- Historical membership assignments are deterministic evidence because
   -- the legacy management-level constraint allows only these three values.
   select count(*) filter(where m.member_role in ('company_superadmin','company_admin')),
          count(*) filter(where m.member_role='employee')
     into v_admin,v_employee
   from iam.membership_roles mr join iam.memberships m
     on m.tenant_id=mr.tenant_id and m.id=mr.membership_id
   where mr.tenant_id=r.tenant_id and mr.role_id=r.id;
   v_admin:=coalesce(v_admin,0); v_employee:=coalesce(v_employee,0);

   if v_admin>0 and v_employee>0 then
     v_clone_key:=r.role_key||'_employee_phase1_'||left(replace(r.id::text,'-',''),8);
     insert into iam.roles(tenant_id,role_key,label,role_family,protected,active,created_by)
     values(r.tenant_id,v_clone_key,r.label||' (Employee)','employee',false,true,r.created_by)
     returning id into v_clone_id;
     insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write,active)
     select v_clone_id,permission_key,scope_kind,can_read,can_write,active
       from iam.role_permissions where role_id=r.id;

     for a in select mr.* from iam.membership_roles mr join iam.memberships m
       on m.tenant_id=mr.tenant_id and m.id=mr.membership_id
       where mr.tenant_id=r.tenant_id and mr.role_id=r.id and mr.revoked_at is null
         and m.member_role='employee' order by mr.id
     loop
       insert into iam.membership_roles(tenant_id,membership_id,role_id,starts_at,ends_at,granted_by)
       values(a.tenant_id,a.membership_id,v_clone_id,a.starts_at,a.ends_at,a.granted_by)
       returning id into v_new_assignment;
       insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by,granted_at,ends_at,revoked_at,revoked_by,revoke_reason)
       select tenant_id,v_new_assignment,site_id,granted_by,granted_at,ends_at,revoked_at,revoked_by,revoke_reason
         from iam.membership_role_sites where tenant_id=a.tenant_id and membership_role_id=a.id;
       insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by,granted_at,ends_at,revoked_at,revoked_by,revoke_reason)
       select tenant_id,v_new_assignment,org_unit_id,granted_by,granted_at,ends_at,revoked_at,revoked_by,revoke_reason
         from iam.membership_role_org_units where tenant_id=a.tenant_id and membership_role_id=a.id;
       update iam.membership_roles set revoked_at=now(),revoked_by=a.granted_by,
         revoke_reason='Automated family split by migration 202611210003; original grantor retained as legacy actor attribution'
       where tenant_id=a.tenant_id and id=a.id;
     end loop;
     update iam.roles set role_family='admin' where id=r.id;
   elsif v_admin>0 then
     update iam.roles set role_family='admin' where id=r.id;
   elsif v_employee>0 then
     update iam.roles set role_family='employee' where id=r.id;
   else
     insert into iam.phase1_role_family_review(tenant_id,role_id,role_key,reason)
     values(r.tenant_id,r.id,r.role_key,'No membership assignment provides deterministic Admin/Employee family evidence')
     on conflict(tenant_id,role_id) do update set reason=excluded.reason;
   end if;
 end loop;
end $$;

alter table iam.roles add constraint roles_phase1_family_not_null_check
 check(tenant_id is null or (role_family is not null and role_family in ('admin','employee'))) not valid;

commit;
