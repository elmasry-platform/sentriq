-- 053: direct inserts into the assignment tables honor the superadmin capability limit. Needs 048-053.
begin;
select extensions.plan(18);
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
reset role;
select set_config('sentriq.migration_runner','on',true);
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
 values('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000002','role_assignment',false,false,'c0000000-0000-0000-0000-000000000001','Probe limit');
select set_config('sentriq.migration_runner','off',true);
-- G01 control: the limited superadmin is refused by the RPC (existing behavior)
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'Limit probe')$q$,'42501','tenant_role_assignment_not_delegated','G01 control: limited superadmin cannot assign a tenant-scope role through the RPC');
select extensions.throws_ok($q$insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),'c0000000-0000-0000-0000-000000000002')$q$,'42501','tenant_role_assignment_not_delegated','G02 limited superadmin cannot INSERT a tenant-scope assignment directly either');
reset role;
select extensions.is((select count(*) from iam.membership_roles where membership_id='c2000000-0000-0000-0000-000000000010' and revoked_at is null)::int,1,'G03 nothing was written (only the baseline assignment is live)');
-- site-only role: the role row has no tenant-scope permission, the site row is the guarded one
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,granted_by) values ('c8000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000002',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000002' and status='published'),'c0000000-0000-0000-0000-000000000002');
select extensions.throws_ok($q$insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c8000000-0000-0000-0000-000000000001','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002')$q$,'42501','site_role_assignment_scope_not_delegated','G04 limited superadmin cannot INSERT a site binding directly');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,granted_by) values ('c8000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000003',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000003' and status='published'),'c0000000-0000-0000-0000-000000000002');
select extensions.throws_ok($q$insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c8000000-0000-0000-0000-000000000002','c4000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002')$q$,'42501','org_role_assignment_scope_not_delegated','G05 limited superadmin cannot INSERT an org-unit binding directly');
reset role;
-- controls: an unlimited superadmin (SB, m03) keeps every direct write
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.lives_ok($q$insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,granted_by) values ('c8000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000009','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),'c0000000-0000-0000-0000-000000000003')$q$,'G06 control: unlimited superadmin can INSERT a tenant-scope assignment directly');
select extensions.lives_ok($q$insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c8000000-0000-0000-0000-000000000001','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000003')$q$,'G07 control: unlimited superadmin can INSERT a site binding directly');
select extensions.lives_ok($q$insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c8000000-0000-0000-0000-000000000002','c4000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000003')$q$,'G08 control: unlimited superadmin can INSERT an org-unit binding directly');
select extensions.lives_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'RPC control')$q$,'G09 control: unlimited superadmin can still assign through the RPC');
reset role;
reset role;
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002');
insert into iam.org_unit_access(tenant_id,membership_id,org_unit_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','c4000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002');
-- RPC controls: delegated admins (not superadmins) must get the same answers with 053 as without it
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000005',true);
set local role authenticated;
select extensions.lives_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c5000000-0000-0000-0000-000000000002',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000002' and status='published'),array['c3000000-0000-0000-0000-000000000001'::uuid],null,now(),null,'RPC control site')$q$,'G10 site-envelope admin assigns a site role at its site through the RPC');
select extensions.throws_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c5000000-0000-0000-0000-000000000002',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000002' and status='published'),array['c3000000-0000-0000-0000-000000000002'::uuid],null,now(),null,'RPC site other')$q$,'42501','site_role_assignment_scope_not_delegated','G11 site-envelope admin is refused at another site');
select extensions.throws_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'RPC tenant role')$q$,'42501','tenant_role_assignment_not_delegated','G12 site-envelope admin is refused a tenant-scope role');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000006',true);
set local role authenticated;
select extensions.lives_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','c5000000-0000-0000-0000-000000000003',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000003' and status='published'),null,array['c4000000-0000-0000-0000-000000000001'::uuid],now(),null,'RPC control org')$q$,'G13 org-envelope admin assigns an org-unit role at its unit through the RPC');
select extensions.throws_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','c5000000-0000-0000-0000-000000000003',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000003' and status='published'),null,array['c4000000-0000-0000-0000-000000000002'::uuid],now(),null,'RPC org other')$q$,'42501','org_role_assignment_scope_not_delegated','G14 org-envelope admin is refused at another unit');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a',(select id from iam.membership_roles where membership_id='c2000000-0000-0000-0000-000000000008' and role_id='c5000000-0000-0000-0000-000000000001' and revoked_at is null),'Probe revoke G09 role');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000004',true);
set local role authenticated;
select extensions.lives_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'RPC tenant env')$q$,'G15 tenant-envelope admin assigns a tenant-scope role to an employee through the RPC');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.revoke_delegation('c1000000-0000-0000-0000-00000000000a',(select id from mx where k='ET'),'Probe revoke tenant envelope');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
insert into mx select api.create_delegation('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','employees_default',null,null,array['role_assignment'],now(),null,'Probe employees default');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000004',true);
set local role authenticated;
select extensions.lives_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'RPC employees default')$q$,'G16 employees_default admin assigns a tenant-scope role to an employee through the RPC');
select extensions.throws_ok($q$select api.assign_membership_role('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000006','c5000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='c5000000-0000-0000-0000-000000000001' and status='published'),null,null,now(),null,'RPC emp default admin')$q$,'23514','role_family_target_mismatch','G17 employees_default admin is refused for a non-employee target (RPC rule, unchanged)');
reset role;
select extensions.is((select count(*) from iam.membership_roles r where r.tenant_id='c1000000-0000-0000-0000-00000000000a' and r.revoked_at is null and r.source_delegation_id is not null and (r.membership_id,r.role_id) in (('c2000000-0000-0000-0000-000000000007'::uuid,'c5000000-0000-0000-0000-000000000002'::uuid),('c2000000-0000-0000-0000-000000000011','c5000000-0000-0000-0000-000000000003'),('c2000000-0000-0000-0000-000000000010','c5000000-0000-0000-0000-000000000001')))::int,3,'G18 the allowed RPC assignments G10, G13, G16 are active with their delegation source (G15 ends with its tenant envelope, which is revoked before G16)');
select * from extensions.finish();
rollback;
