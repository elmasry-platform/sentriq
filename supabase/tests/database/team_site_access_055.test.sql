-- 055: a company Admin reads site_access rows of Employees of the same tenant. The test embeds the rollback (to rebuild the old state,
-- because CI applies every migration first) and the migration (checked against the files by scripts/check_055_embed.sh). Rolled back at the end.
begin;
select extensions.plan(23);
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('c0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','s-'||i||'@example.test',now(),now(),now() from generate_series(1,11) i;
select private.bootstrap_platform_owner('c0000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values ('c1000000-0000-0000-0000-00000000000a','Sites A','c0000000-0000-0000-0000-000000000001'),('c1000000-0000-0000-0000-00000000000b','Sites B','c0000000-0000-0000-0000-000000000001');
-- A: u2 superadmin, u3 admin (tested), u4 admin (peer), u5/u6/u7 employees (u6 suspended, u7 ended), u11 suspended admin. B: u8 superadmin, u9 admin, u10 employee.
insert into iam.memberships(id,tenant_id,user_id,member_role,email,status) values
 ('c2000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000002','company_superadmin','s-2@example.test','active'),
 ('c2000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000003','company_admin','s-3@example.test','active'),
 ('c2000000-0000-0000-0000-000000000004','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000004','company_admin','s-4@example.test','active'),
 ('c2000000-0000-0000-0000-000000000005','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000005','employee','s-5@example.test','active'),
 ('c2000000-0000-0000-0000-000000000006','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000006','employee','s-6@example.test','active'),
 ('c2000000-0000-0000-0000-000000000007','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000007','employee','s-7@example.test','active'),
 ('c2000000-0000-0000-0000-000000000008','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000008','company_superadmin','s-8@example.test','active'),
 ('c2000000-0000-0000-0000-000000000009','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000009','company_admin','s-9@example.test','active'),
 ('c2000000-0000-0000-0000-000000000010','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000010','employee','s-10@example.test','active'),
 ('c2000000-0000-0000-0000-000000000011','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000011','company_admin','s-11@example.test','active');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select t,'hse',now()-interval '1 day',now()+interval '30 days','c0000000-0000-0000-0000-000000000001','Sites fixture entitlement','complimentary' from unnest(array['c1000000-0000-0000-0000-00000000000a'::uuid,'c1000000-0000-0000-0000-00000000000b'::uuid]) t;
select set_config('sentriq.migration_runner','on',true);
update iam.memberships set status='suspended' where id in ('c2000000-0000-0000-0000-000000000006','c2000000-0000-0000-0000-000000000011');
update iam.memberships set status='ended' where id='c2000000-0000-0000-0000-000000000007';
select set_config('sentriq.migration_runner','off',true);
insert into core.sites(id,tenant_id,name,code) values ('c3000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','Site 1','S1'),('c3000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','Site 2','S2'),('c3000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000b','Site B','SB');
-- site rows: every member of A has one (SA, admin u3, peer admin u4, suspended admin u11, employees u5 two sites, u6, u7), B has two
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000002','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000003','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','c3000000-0000-0000-0000-000000000002','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005','c3000000-0000-0000-0000-000000000002','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000006','c3000000-0000-0000-0000-000000000002','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),
 ('c1000000-0000-0000-0000-00000000000b','c2000000-0000-0000-0000-000000000008','c3000000-0000-0000-0000-000000000003','c0000000-0000-0000-0000-000000000008'),('c1000000-0000-0000-0000-00000000000b','c2000000-0000-0000-0000-000000000010','c3000000-0000-0000-0000-000000000003','c0000000-0000-0000-0000-000000000008');
select set_config('request.jwt.claim.role','authenticated',true);
create function pg_temp.sites(u uuid) returns text language plpgsql as $f$ begin
 perform set_config('request.jwt.claim.sub',u::text,true);
 return coalesce((select string_agg(right(membership_id::text,2)||'@'||right(site_id::text,1),',' order by membership_id,site_id) from iam.site_access),'');
end $f$;
grant execute on function pg_temp.sites(uuid) to authenticated;
create function pg_temp.sids(u uuid, wk text) returns text language plpgsql as $f$ begin
 perform set_config('request.jwt.claim.sub',u::text,true);
 return coalesce((select "siteIds"::text from api.v_memberships where "workspaceId"=wk::uuid and "membershipId"='c2000000-0000-0000-0000-000000000005'),'(row hidden)');
end $f$;
grant execute on function pg_temp.sids(uuid,text) to authenticated;
reset role;
-- BEGIN EMBEDDED 055 ROLLBACK
-- Rollback of 055: restore the earlier site_access_read policy and drop the helper.
drop policy if exists site_access_read on iam.site_access;
create policy site_access_read on iam.site_access for select to authenticated
 using (private.can_manage_tenant(tenant_id)
        or (exists (select 1 from iam.memberships m
                     where m.id = site_access.membership_id and m.user_id = (select auth.uid()))));
drop function if exists private.admin_can_read_employee_member(uuid, uuid);
-- END EMBEDDED 055 ROLLBACK
-- BEFORE 055: positive controls (the behavior the change replaces)
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000003'),'03@1','S01 before 055 an admin sees only its own site row');
select extensions.is(pg_temp.sids('c0000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a'),case when to_regprocedure('private.is_active_company_admin(uuid)') is not null then '[]' else '(row hidden)' end,'S02 before 055 an admin gets no site ids for an employee (empty with 054, row hidden without it)');
reset role;
-- BEGIN EMBEDDED 055
-- 055: a company Admin reads the site assignments (iam.site_access) of EMPLOYEE-level members of the same tenant.
-- Product decision as relayed by Main (not verified by me against the original): "he sees them normally".
-- Level comes only from iam.memberships.member_role, so a temporary permission, delegation or grant cannot widen it.
-- Never Superadmin rows, never other Admin rows, never another tenant. Own rows and Superadmin access are unchanged.
-- Read only: site_access_insert and site_access_update are not touched. Feeds api.v_memberships."siteIds".
-- Independent of 054 (the helper below does its own admin check and does not depend on memberships RLS).
-- Rollback: supabase/rollbacks/202611250055_admin_reads_employee_site_access.rollback.sql. Plain PostgreSQL. No data change.

create or replace function private.admin_can_read_employee_member(p_tenant_id uuid, p_membership_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1
     from iam.memberships a
     join core.tenants t on t.id = a.tenant_id
     join iam.memberships e on e.tenant_id = a.tenant_id
    where a.tenant_id = p_tenant_id
      and a.user_id = auth.uid()
      and a.member_role = 'company_admin' and a.status = 'active' and t.status = 'active'
      and e.id = p_membership_id and e.member_role = 'employee')
$$;
revoke all on function private.admin_can_read_employee_member(uuid, uuid) from public, anon;
grant execute on function private.admin_can_read_employee_member(uuid, uuid) to authenticated;

drop policy if exists site_access_read on iam.site_access;
create policy site_access_read on iam.site_access for select to authenticated
 using (private.can_manage_tenant(tenant_id)
        or (exists (select 1 from iam.memberships m
                     where m.id = site_access.membership_id and m.user_id = (select auth.uid())))
        or private.admin_can_read_employee_member(tenant_id, membership_id));
-- END EMBEDDED 055
-- AFTER 055
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000003'),'03@1,05@1,05@2,06@2,07@1','T01 admin sees its own row and the site rows of all employees of its tenant (any status)');
select extensions.is((select count(*) from iam.site_access where membership_id='c2000000-0000-0000-0000-000000000002')::int,0,'T02 admin sees no superadmin site row');
select extensions.is((select count(*) from iam.site_access where membership_id in ('c2000000-0000-0000-0000-000000000004','c2000000-0000-0000-0000-000000000011'))::int,0,'T03 admin sees no other admin site row (active or suspended)');
select extensions.is((select count(*) from iam.site_access where tenant_id='c1000000-0000-0000-0000-00000000000b')::int,0,'T04 admin sees no other tenant row');
select extensions.is(pg_temp.sids('c0000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a'),case when to_regprocedure('private.is_active_company_admin(uuid)') is not null then '["c3000000-0000-0000-0000-000000000001", "c3000000-0000-0000-0000-000000000002"]' else '(row hidden)' end,'T05 v_memberships.siteIds of an employee: both sites when 054 (member rows for admins) is present, otherwise the row itself is hidden by memberships RLS');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000005',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000005'),'05@1,05@2','T06 employee still sees only its own site rows');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000002'),'02@1,03@1,04@2,05@1,05@2,06@2,07@1,11@1','T07 superadmin still sees all 8 rows of its tenant and none of B');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000008',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000008'),'08@3,10@3','T08 tenant B superadmin sees its own two rows');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000009',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000009'),'10@3','T09 tenant B admin sees only its employee row (own admin has no site row)');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000011',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000011'),'11@1','T10 a suspended admin sees only its own row');
-- temporary access must not widen: envelope for u3 plus a decision on u3 and on u4, compare
reset role;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason) values
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000003','hse.dashboard.read','allow','tenant',true,true,'c0000000-0000-0000-0000-000000000002','temp widen attempt');
select set_config('sentriq.migration_runner','off',true);
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.create_delegation('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000003','tenant',null,null,array['role_assignment'],now(),now()+interval '1 day','Temporary envelope for u3');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is(pg_temp.sites('c0000000-0000-0000-0000-000000000003'),'03@1,05@1,05@2,06@2,07@1','T11 a temporary delegation and decision do not change what the admin sees');
-- read only: an admin cannot change site rows
create function pg_temp.try_write(u uuid) returns void language plpgsql as $f$ begin
 perform set_config('request.jwt.claim.sub',u::text,true);
 begin update iam.site_access set active=false where membership_id='c2000000-0000-0000-0000-000000000005'; exception when others then null; end;
 begin delete from iam.site_access where membership_id='c2000000-0000-0000-0000-000000000005'; exception when others then null; end;
 begin insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c3000000-0000-0000-0000-000000000002','c0000000-0000-0000-0000-000000000003'); exception when others then null; end;
end $f$;
grant execute on function pg_temp.try_write(uuid) to authenticated;
select pg_temp.try_write('c0000000-0000-0000-0000-000000000003');
reset role;
select extensions.is((select count(*) from iam.site_access where membership_id='c2000000-0000-0000-0000-000000000005' and active)::int,2,'T12 an admin cannot update or delete employee site rows');
select extensions.is((select count(*) from iam.site_access where membership_id='c2000000-0000-0000-0000-000000000007')::int,1,'T13 an admin cannot insert a site row for an employee');
select extensions.ok(not has_function_privilege('anon','private.admin_can_read_employee_member(uuid,uuid)','execute'),'T14 anon cannot execute the new helper');
select extensions.ok((select qual from pg_policies where schemaname='iam' and tablename='site_access' and policyname='site_access_read') like '%admin_can_read_employee_member%','T15 site_access_read uses the employee-level helper');
select extensions.is((select count(*) from pg_policies where schemaname='iam' and tablename='site_access')::int,4,'T16 site_access still has exactly 4 policies (read, insert, update, platform boundary)');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
select extensions.ok(private.admin_can_read_employee_member('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005'),'T17 helper: active admin, employee of same tenant is true');
select extensions.ok(not private.admin_can_read_employee_member('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004'),'T18 helper: another admin is false');
select extensions.ok(not private.admin_can_read_employee_member('c1000000-0000-0000-0000-00000000000b','c2000000-0000-0000-0000-000000000010'),'T19 helper: employee of another tenant is false');
select extensions.ok(not private.admin_can_read_employee_member('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010'),'T21 helper: admin of A asking about an employee of tenant B (own tenant id passed) is false');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000005',true);
select extensions.ok(not private.admin_can_read_employee_member('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000006'),'T20 helper: an employee caller is false');
select * from extensions.finish();
rollback;
