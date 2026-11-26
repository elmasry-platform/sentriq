-- Restore matrix: black-box round trips of company and member suspend/reactivate through the public RPCs, checking stored state and EFFECTIVE permissions.
-- Fixture is deliberately non-uniform: role assignments with NO scope rows, site-only, org-only, hand-revoked, and not delegated at all.
-- Documents current behavior (migrations 027-031, 034, 048). Needs 048 (superadmin target guard) applied.
begin;
select extensions.plan(28);
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('c0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','rm-'||i||'@example.test',now(),now(),now() from generate_series(1,13) i;
select private.bootstrap_platform_owner('c0000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values
 ('c1000000-0000-0000-0000-00000000000a','Matrix A','c0000000-0000-0000-0000-000000000001'),
 ('c1000000-0000-0000-0000-00000000000b','Matrix B','c0000000-0000-0000-0000-000000000001');
-- A: u2 SA (superadmin), u3 SB (second superadmin, the guarded target), u4 AD1 tenant delegate, u5 AD2 site delegate, u6 AD3 org delegate,
--    u7 E1 (tenant role, NO scope rows), u8 E2 (site role, site only), u9 E3 (org role, org only), u10 E4 (role revoked by hand), u11 E5 (direct role by SA)
-- B: u12 superadmin, u13 employee (control)
insert into iam.memberships(id,tenant_id,user_id,member_role,email) values
 ('c2000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000002','company_superadmin','rm-2@example.test'),
 ('c2000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000003','company_superadmin','rm-3@example.test'),
 ('c2000000-0000-0000-0000-000000000004','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000004','company_admin','rm-4@example.test'),
 ('c2000000-0000-0000-0000-000000000005','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000005','company_admin','rm-5@example.test'),
 ('c2000000-0000-0000-0000-000000000006','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000006','company_admin','rm-6@example.test'),
 ('c2000000-0000-0000-0000-000000000007','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000007','employee','rm-7@example.test'),
 ('c2000000-0000-0000-0000-000000000008','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000008','employee','rm-8@example.test'),
 ('c2000000-0000-0000-0000-000000000009','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000009','employee','rm-9@example.test'),
 ('c2000000-0000-0000-0000-000000000010','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000010','employee','rm-10@example.test'),
 ('c2000000-0000-0000-0000-000000000011','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000011','employee','rm-11@example.test'),
 ('c2000000-0000-0000-0000-000000000012','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000012','company_superadmin','rm-12@example.test'),
 ('c2000000-0000-0000-0000-000000000013','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000013','employee','rm-13@example.test');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select t,'hse',now()-interval '1 day',now()+interval '30 days','c0000000-0000-0000-0000-000000000001','Matrix fixture entitlement','complimentary'
from unnest(array['c1000000-0000-0000-0000-00000000000a'::uuid,'c1000000-0000-0000-0000-00000000000b'::uuid]) t;
insert into core.sites(id,tenant_id,name,code) values
 ('c3000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','Matrix Site 1','MS1'),
 ('c3000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','Matrix Site 2','MS2');
insert into core.org_units(id,tenant_id,name) values
 ('c4000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','Matrix Org 1'),
 ('c4000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','Matrix Org 2');
insert into iam.roles(id,tenant_id,role_key,label,role_family,created_by) values
 ('c5000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','rm_tenant','Matrix Tenant Role','employee','c0000000-0000-0000-0000-000000000001'),
 ('c5000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','rm_site','Matrix Site Role','employee','c0000000-0000-0000-0000-000000000001'),
 ('c5000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a','rm_org','Matrix Org Role','employee','c0000000-0000-0000-0000-000000000001'),
 ('c5000000-0000-0000-0000-000000000004','c1000000-0000-0000-0000-00000000000a','rm_admin','Matrix Admin Role','admin','c0000000-0000-0000-0000-000000000001');
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,org_unit_id,can_read,granted_by,reason) values
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','hse.dashboard.read','allow','tenant',null,null,true,'c0000000-0000-0000-0000-000000000002','Matrix admin authority tenant'),
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','site','c3000000-0000-0000-0000-000000000001',null,true,'c0000000-0000-0000-0000-000000000002','Matrix admin authority site'),
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000006','hse.dashboard.read','allow','org_unit',null,'c4000000-0000-0000-0000-000000000001',true,'c0000000-0000-0000-0000-000000000002','Matrix admin authority org');
select set_config('sentriq.migration_runner','off',true);
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.publish_role_version('c1000000-0000-0000-0000-00000000000a','c5000000-0000-0000-0000-000000000001','[{"permission_key":"hse.dashboard.read","scope_kind":"tenant","can_read":true,"can_write":false}]'::jsonb,'Matrix tenant role');
select api.publish_role_version('c1000000-0000-0000-0000-00000000000a','c5000000-0000-0000-0000-000000000002','[{"permission_key":"hse.dashboard.read","scope_kind":"site","can_read":true,"can_write":false}]'::jsonb,'Matrix site role');
select api.publish_role_version('c1000000-0000-0000-0000-00000000000a','c5000000-0000-0000-0000-000000000004','[{"permission_key":"hse.dashboard.read","scope_kind":"tenant","can_read":true,"can_write":false}]'::jsonb,'Matrix admin role');
select api.publish_role_version('c1000000-0000-0000-0000-00000000000a','c5000000-0000-0000-0000-000000000003','[{"permission_key":"hse.dashboard.read","scope_kind":"org_unit","can_read":true,"can_write":false}]'::jsonb,'Matrix org role');
create temporary table mx(k text primary key, id uuid);
grant select,insert on table pg_temp.mx to authenticated;
insert into mx select 'ET',api.create_delegation('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),null,'Matrix tenant envelope');
insert into mx select 'ES',api.create_delegation('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005','site','c3000000-0000-0000-0000-000000000001',null,array['role_assignment'],now(),null,'Matrix site envelope');
insert into mx select 'EO',api.create_delegation('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000006','org_unit',null,'c4000000-0000-0000-0000-000000000001',array['role_assignment'],now(),null,'Matrix org envelope');
reset role;
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002');
insert into iam.org_unit_access(tenant_id,membership_id,org_unit_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000009','c4000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002'),('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000006','c4000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002');
-- E5: direct assignment by the superadmin (not delegated)
set local role authenticated;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
insert into mx select 'R5',api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'Matrix direct assignment');
reset role;

select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000004',true);
set local role authenticated;
insert into mx select 'A1',api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'Matrix delegated tenant role');
insert into mx select 'A4',api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'Matrix role to be revoked by hand');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000005',true);
set local role authenticated;
insert into mx select 'A2',api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','c5000000-0000-0000-0000-000000000002',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000002' and status='published'),array['c3000000-0000-0000-0000-000000000001'::uuid],null,now(),null,'Matrix delegated site role');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000006',true);
set local role authenticated;
insert into mx select 'A3',api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000009','c5000000-0000-0000-0000-000000000003',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000003' and status='published'),null,array['c4000000-0000-0000-0000-000000000001'::uuid],now(),null,'Matrix delegated org role');
reset role;
insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,granted_by) values ('c6000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000003','c5000000-0000-0000-0000-000000000004',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000004' and status='published'),'c0000000-0000-0000-0000-000000000002');
insert into mx values('SBR','c6000000-0000-0000-0000-000000000001');
create function pg_temp.eff(u text, site uuid, org uuid) returns text language plpgsql as $f$ begin perform set_config('request.jwt.claim.sub',u,true); return private.phase1_permission_allowed('c1000000-0000-0000-0000-00000000000a','hse.dashboard.read',site,org,false,null,null)::text; end $f$;
create function pg_temp.st() returns text language sql as $f$ select string_agg(k||'='||case when r.revoked_at is null then 'live' else 'revoked' end||case when r.suspended_by_tenant then '+mark' else '' end, ' ' order by k) from mx join iam.membership_roles r on r.id=mx.id where k in ('A1','A2','A3','A4','R5') $f$;
create function pg_temp.effs() returns text language sql as $f$ select 'E1='||pg_temp.eff('c0000000-0000-0000-0000-000000000007',null,null)||' E2s1='||pg_temp.eff('c0000000-0000-0000-0000-000000000008','c3000000-0000-0000-0000-000000000001',null)||' E2s2='||pg_temp.eff('c0000000-0000-0000-0000-000000000008','c3000000-0000-0000-0000-000000000002',null)||' E3o1='||pg_temp.eff('c0000000-0000-0000-0000-000000000009',null,'c4000000-0000-0000-0000-000000000001')||' E4='||pg_temp.eff('c0000000-0000-0000-0000-000000000010',null,null)||' E5='||pg_temp.eff('c0000000-0000-0000-0000-000000000011',null,null) $f$;
select extensions.ok((select count(*)=0 from iam.membership_role_sites s join mx on mx.id=s.membership_role_id where mx.k in ('A1','A4','R5')) and (select count(*)=0 from iam.membership_role_org_units s join mx on mx.id=s.membership_role_id where mx.k in ('A1','A4','R5')) and (select count(*)=1 from iam.membership_role_sites s join mx on mx.id=s.membership_role_id where mx.k='A2') and (select count(*)=1 from iam.membership_role_org_units s join mx on mx.id=s.membership_role_id where mx.k='A3') and (select bool_and(source_delegation_id is not null) from iam.membership_roles r join mx on mx.id=r.id where mx.k in ('A1','A2','A3','A4')) and (select source_delegation_id is null from iam.membership_roles r join mx on mx.id=r.id where mx.k='R5'),'M01 fixture shape: A1 and A4 have no scope rows, A2 site only, A3 org only, all four delegated, R5 direct');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=true E5=true','M02 baseline effective permissions: site role holds only its site, org role only its org unit');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a',(select id from mx where k='A4'),'Matrix manual revoke');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=live','M03 manual revoke of a no-scope assignment succeeds and carries no company mark');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=true','M04 the hand-revoked member loses the permission, nobody else changes');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('c1000000-0000-0000-0000-00000000000a','suspended','Matrix pause');
reset role;
select extensions.is(pg_temp.st(),'A1=revoked+mark A2=revoked+mark A3=revoked+mark A4=revoked R5=live','M05 company suspension marks exactly the delegated live assignments; hand revoke stays unmarked, direct assignment untouched');
select extensions.is(pg_temp.effs(),'E1=false E2s1=false E2s2=false E3o1=false E4=false E5=false','M06 nobody holds the permission while the company is suspended');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('c1000000-0000-0000-0000-00000000000a','active','Matrix return');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=live','M07 company reactivation restores the three marked assignments (no-scope, site-only, org-only) and not the hand-revoked one');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=true','M08 effective permissions after the round trip equal the baseline minus the hand revoke (site and org scope not widened)');
select extensions.is((select count(*) from audit.events where action_key='iam.delegation_source.restored' and tenant_id='c1000000-0000-0000-0000-00000000000a' and record_id in (select id from mx where k in ('A1','A2','A3')))::int,3,'M09 one restore audit row per restored assignment');
select extensions.is((select count(*) from iam.membership_role_sites s join mx on mx.id=s.membership_role_id where mx.k='A2' and s.revoked_at is null)::int+(select count(*) from iam.membership_role_org_units s join mx on mx.id=s.membership_role_id where mx.k='A3' and s.revoked_at is null)::int,2,'M10 scope binding rows were never touched by the round trip');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('c1000000-0000-0000-0000-00000000000a','suspended','Matrix pause 2');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('c1000000-0000-0000-0000-00000000000a','active','Matrix return 2');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=live','M11 second cycle gives the same stored state');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=true','M12 second cycle gives the same effective permissions');
select extensions.ok((select count(*)=6 from iam.membership_roles where tenant_id='c1000000-0000-0000-0000-00000000000a') and (select count(*)=6 from audit.events where action_key='iam.delegation_source.restored' and tenant_id='c1000000-0000-0000-0000-00000000000a'),'M13 repeat cycles create no duplicate role rows (6 total) and exactly one restore audit row per assignment per cycle (6)');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a','c6000000-0000-0000-0000-000000000001','Matrix SA tries SB')$q$,'42501','superadmin_target_requires_operator','M14 048 guard after the round trip: a company superadmin cannot revoke another superadmin assignment that has NO scope rows');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($q$update iam.membership_roles set ends_at=now()+interval '1 day' where id='c6000000-0000-0000-0000-000000000001'$q$,'42501','superadmin_target_requires_operator','M15 048 guard after the round trip: direct write on the superadmin assignment is refused');
reset role;
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id='c6000000-0000-0000-0000-000000000001'),'M16 superadmin own assignment was not touched by two company cycles or the refused attempts');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('c1000000-0000-0000-0000-00000000000a','suspended','Matrix pause 3');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a',(select id from mx where k='A1'),'Matrix revoke while suspended')$q$,'42501','assignment_revocation_outside_envelope','M17 while the company is suspended even its superadmin cannot revoke a marked assignment');
reset role;
select extensions.is(pg_temp.st(),'A1=revoked+mark A2=revoked+mark A3=revoked+mark A4=revoked R5=live','M18 the refused revoke changed nothing');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','suspended','Matrix independent member cause');
reset role;
select extensions.is(pg_temp.st(),'A1=revoked+mark A2=revoked A3=revoked+mark A4=revoked R5=live','M19 an independent cause during the suspension (member suspended) clears the company mark on that member only');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('c1000000-0000-0000-0000-00000000000a','active','Matrix return 3');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=revoked A3=live A4=revoked R5=live','M20 company reactivation restores A1 and A3 but not A2 (independent cause) and not A4 (hand revoke)');
select extensions.is(pg_temp.effs(),'E1=true E2s1=false E2s2=false E3o1=true E4=false E5=true','M21 effective: the member with the independent cause stays without the permission');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','active','Matrix member return');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=revoked A3=live A4=revoked R5=live','M22 reactivating the member does not bring the assignment back');
select extensions.ok((select count(*)=1 from iam.site_access where tenant_id='c1000000-0000-0000-0000-00000000000a' and membership_id='c2000000-0000-0000-0000-000000000008' and active),'M23 reactivating a member keeps its unchanged site access (current behavior, migration 050 restore)');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','suspended','Matrix E1 pause');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','active','Matrix E1 return');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=revoked A3=live A4=revoked R5=live','M24 member suspend then reactivate keeps that member delegated role (current behavior, migration 050 restore); the earlier revoked ones stay revoked');
select extensions.is(pg_temp.effs(),'E1=true E2s1=false E2s2=false E3o1=true E4=false E5=true','M25 effective: the cycled member holds the permission again; the earlier independent cause member stays without it');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','suspended','AD1 pause');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','active','AD1 return');
reset role;
select extensions.is((select status||'/'||suspended_by_tenant::text from iam.delegation_envelopes where id=(select id from mx where k='ET')),'suspended/false','M26 a delegate own member cycle leaves its envelope suspended without a company mark (no laundering back)');
select extensions.is((select string_agg(status,',') from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000004'),'active','M27 the delegate direct decision is restored after the member returns (current behavior, migration 050 restore)');
select extensions.is(pg_temp.eff('c0000000-0000-0000-0000-000000000004',null,null),'true','M28 effective: the cycled delegate holds its own direct permission again (the envelope stays suspended, M26)');
select * from extensions.finish();
rollback;