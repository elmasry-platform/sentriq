-- 050 membership restore on reactivation: suspend/reactivate round trips through the public RPCs.
begin;
select extensions.plan(41);
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

create function pg_temp.opset(m text, s text, why text) returns void language plpgsql as $f$ begin
 perform set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
 set local role authenticated;
 perform api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a',m::uuid,s,why);
 reset role; end $f$;
grant execute on function pg_temp.opset(text,text,text) to authenticated;
create function pg_temp.ca(m text) returns text language sql as $f$ select
 (select count(*) from iam.site_access where membership_id=m::uuid and active)||'/'||(select count(*) from iam.org_unit_access where membership_id=m::uuid and active)||'/'||
 (select count(*) from iam.membership_roles where membership_id=m::uuid and revoked_at is null) $f$;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a',(select id from mx where k='A4'),'T50 manual revoke');
reset role;
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=live','T01 baseline stored state (A4 hand-revoked)');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=true','T02 baseline effective permissions');
select pg_temp.opset('c2000000-0000-0000-0000-000000000007','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','suspended','t50');
select extensions.is(pg_temp.effs(),'E1=false E2s1=false E2s2=false E3o1=false E4=false E5=false','C1a cycle 1: nobody holds the permission while suspended');
select pg_temp.opset('c2000000-0000-0000-0000-000000000007','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','active','t50');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=true','C1b cycle 1: effective permissions after reactivation equal the baseline');
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=live','C1c cycle 1: stored role state equals the baseline (hand revoke stays revoked, nothing extra back)');
select extensions.is(pg_temp.ca('c2000000-0000-0000-0000-000000000008')||' '||pg_temp.ca('c2000000-0000-0000-0000-000000000009'),'1/0/1 0/1/1','C1d cycle 1: site and org access rows are back for the site and org members');
select pg_temp.opset('c2000000-0000-0000-0000-000000000007','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','suspended','t50');
select extensions.is(pg_temp.effs(),'E1=false E2s1=false E2s2=false E3o1=false E4=false E5=false','C2a cycle 2: nobody holds the permission while suspended');
select pg_temp.opset('c2000000-0000-0000-0000-000000000007','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','active','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','active','t50');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=true','C2b cycle 2: effective permissions after reactivation equal the baseline');
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=live','C2c cycle 2: stored role state equals the baseline (hand revoke stays revoked, nothing extra back)');
select extensions.is(pg_temp.ca('c2000000-0000-0000-0000-000000000008')||' '||pg_temp.ca('c2000000-0000-0000-0000-000000000009'),'1/0/1 0/1/1','C2d cycle 2: site and org access rows are back for the site and org members');
select extensions.ok((select count(*)=10 from iam.membership_suspension_snapshots where tenant_id='c1000000-0000-0000-0000-00000000000a' and status='restored' and outcome->>'mode'='restored'),'C3 five members x two cycles produced ten restored snapshots and no clean-slate reset');
select extensions.ok((select count(*)=10 from audit.events where tenant_id='c1000000-0000-0000-0000-00000000000a' and action_key='iam.membership.access_restore'),'C4 each reactivation wrote an audit event');
select extensions.ok((select count(*)=0 from iam.membership_roles where tenant_id='c1000000-0000-0000-0000-00000000000a' and revoke_reason='Reset on membership reactivation'),'C5 no assignment was revoked by the old reset');
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','suspended','t50');
update iam.membership_roles set revoked_at=now(),revoked_by='c0000000-0000-0000-0000-000000000002',revoke_reason='T50 hand revoke while suspended' where id=(select id from mx where k='R5');
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','active','t50');
select extensions.is(pg_temp.st(),'A1=live A2=live A3=live A4=revoked R5=revoked','D1 an assignment hand-revoked during the suspension stays revoked');
select extensions.is(pg_temp.effs(),'E1=true E2s1=true E2s2=false E3o1=true E4=false E5=false','D2 effective permission of the hand-revoked member stays off, others unchanged');
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','suspended','t50');
update iam.membership_role_sites set revoked_at=now(),revoked_by='c0000000-0000-0000-0000-000000000002',revoke_reason='T50 site removed' where membership_role_id=(select id from mx where k='A2');
update iam.site_access set active=false where membership_id='c2000000-0000-0000-0000-000000000008';
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','active','t50');
select extensions.is(pg_temp.effs(),'E1=true E2s1=false E2s2=false E3o1=true E4=false E5=false','D3 a site removed during the suspension is not brought back');
select extensions.is(pg_temp.ca('c2000000-0000-0000-0000-000000000008'),'0/0/1','D4 site access stays inactive; the role itself is still live');
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','suspended','t50');
update iam.roles set active=false where id='c5000000-0000-0000-0000-000000000003';
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','active','t50');
select extensions.is(pg_temp.st(),'A1=live A2=live A3=revoked A4=revoked R5=revoked','D5 an assignment whose role was archived during the suspension is not restored');
select extensions.is(pg_temp.effs(),'E1=true E2s1=false E2s2=false E3o1=false E4=false E5=false','D6 effective permission follows the archived role');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','suspended','t50');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','active','t50');
select extensions.is(pg_temp.ca('c2000000-0000-0000-0000-000000000010'),'0/0/0','D7 access added while suspended is not live after reactivation (no privilege gain)');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','suspended','t50');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c3000000-0000-0000-0000-000000000002','c0000000-0000-0000-0000-000000000002') on conflict(tenant_id,membership_id,site_id) do update set active=true;
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','ended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','active','t50');
select extensions.is(pg_temp.ca('c2000000-0000-0000-0000-000000000010'),'0/0/0','D8 suspended then ended then active is a clean slate');
select extensions.ok((select count(*)=1 from iam.membership_suspension_snapshots where membership_id='c2000000-0000-0000-0000-000000000010' and status='discarded' and outcome->>'mode'='clean_slate'),'D9 the snapshot of that path is closed as clean_slate');
select pg_temp.opset('c2000000-0000-0000-0000-000000000005','suspended','t50');
update iam.member_permission_decisions set starts_at=now()-interval '2 days',ends_at=now()-interval '1 day' where membership_id='c2000000-0000-0000-0000-000000000005';
select pg_temp.opset('c2000000-0000-0000-0000-000000000005','active','t50');
select extensions.ok((select count(*)=0 from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000005' and status='active'),'E1 an expired decision stays down after reactivation');
select pg_temp.opset('c2000000-0000-0000-0000-000000000004','suspended','t50');
select extensions.ok((select string_agg(status,',')='suspended' from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000004'),'E2 the delegate decision is suspended while the member is suspended');
select pg_temp.opset('c2000000-0000-0000-0000-000000000004','active','t50');
select extensions.ok((select string_agg(status,',')='active' from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000004'),'E3 the delegate direct decision is active again after reactivation');
select extensions.is(pg_temp.eff('c0000000-0000-0000-0000-000000000004',null,null),'true','E4 effective: the reactivated delegate holds the permission again');
select extensions.ok((select status='suspended' from iam.delegation_envelopes where id=(select id from mx where k='ET')),'E5 the delegate envelope stays suspended (not restored by this change)');
create temp table aud0(n bigint); grant select,insert on table pg_temp.aud0 to authenticated;
insert into aud0 select (select count(*) from audit.events where tenant_id='c1000000-0000-0000-0000-00000000000a' and action_key='iam.membership.access_restore');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','c3000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002') on conflict(tenant_id,membership_id,site_id) do update set active=true;
update iam.memberships set status='invited' where id='c2000000-0000-0000-0000-000000000010';
select pg_temp.opset('c2000000-0000-0000-0000-000000000010','active','t50');
select extensions.is(pg_temp.ca('c2000000-0000-0000-0000-000000000010'),'0/0/0','F1 invited then active is a clean slate');
select extensions.ok(((select count(*) from audit.events where tenant_id='c1000000-0000-0000-0000-00000000000a' and action_key='iam.membership.access_restore'))=(select n from aud0),'F2 invited to active writes no restore audit row (no snapshot)');
select pg_temp.opset('c2000000-0000-0000-0000-000000000006','suspended','t50');
update iam.memberships set member_role='employee' where id='c2000000-0000-0000-0000-000000000006';
select pg_temp.opset('c2000000-0000-0000-0000-000000000006','active','t50');
select extensions.ok((select outcome->>'mode'='clean_slate' from iam.membership_suspension_snapshots where membership_id='c2000000-0000-0000-0000-000000000006' and status='discarded' order by taken_at desc limit 1),'F3 member role changed while suspended gives a clean slate');
select extensions.ok((select string_agg(status,',')='suspended' from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000006'),'F4 the decision of a role-changed member stays suspended');
create function public.t50_force_fail() returns trigger language plpgsql as $f$ begin if old.status='suspended' and new.status='active' then raise exception 't50 forced'; end if; return new; end $f$;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000002','T50 forced failure fixture');
select set_config('sentriq.migration_runner','off',true);
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','suspended','t50');
create trigger t50_force_fail before update on iam.member_permission_decisions for each row execute function public.t50_force_fail();
select pg_temp.opset('c2000000-0000-0000-0000-000000000011','active','t50');
drop trigger t50_force_fail on iam.member_permission_decisions;
select extensions.ok((select status='active' from iam.memberships where id='c2000000-0000-0000-0000-000000000011'),'F5 reactivation still succeeds when the restore step errors');
select extensions.ok((select outcome->>'mode'='clean_slate' and outcome ? 'restore_failed' from iam.membership_suspension_snapshots where membership_id='c2000000-0000-0000-0000-000000000011' and status='discarded' order by taken_at desc limit 1),'F6 the failed restore fell back to a clean slate and recorded why');
select extensions.ok((select string_agg(status,',')='suspended' from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000011' and reason like 'T50 forced%'),'F7 the decision stays down after the fallback');
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason,protected_origin) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000009','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000001','T50 protected fixture',true);
select set_config('sentriq.migration_runner','off',true);
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason,protected_origin) values ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','hse.forms.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000001','T50 protected fixture',true);
select set_config('sentriq.migration_runner','off',true);
select set_config('sentriq.operator_decision_actor','c0000000-0000-0000-0000-000000000001',true);
select pg_temp.opset('c2000000-0000-0000-0000-000000000009','suspended','t50');
select set_config('sentriq.operator_decision_actor','',true);
select set_config('request.jwt.claim.sub','',true);
update iam.memberships set status='active' where id='c2000000-0000-0000-0000-000000000009';
select extensions.ok((select status='suspended' from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000009' and protected_origin),'F8 a protected-origin decision stays down when a non-operator reactivates');
select set_config('sentriq.operator_decision_actor','c0000000-0000-0000-0000-000000000001',true);
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000008','active','t50');
select set_config('sentriq.operator_decision_actor','',true);
select extensions.ok((select status='active' from iam.member_permission_decisions where membership_id='c2000000-0000-0000-0000-000000000008' and protected_origin),'F9 a protected-origin decision comes back when an operator reactivates');
select pg_temp.opset('c2000000-0000-0000-0000-000000000003','suspended','t50');
select pg_temp.opset('c2000000-0000-0000-0000-000000000003','active','t50');
select extensions.ok((select revoked_at is null from iam.membership_roles where id='c6000000-0000-0000-0000-000000000001'),'G1 the superadmin own assignment is untouched by the cycle');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a','c6000000-0000-0000-0000-000000000001','T50 SA tries SB')$q$,'42501','superadmin_target_requires_operator','G2 048 guard still blocks a superadmin from revoking another superadmin assignment after the cycle');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000007',true);
set local role authenticated;
select extensions.throws_ok($q$select * from api.membership_restore_report('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008')$q$,'42501','membership_restore_report_not_allowed','G3 a plain employee cannot read the restore report');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.ok((select count(*)>=2 from api.membership_restore_report('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008')),'G4 a company superadmin can read the restore report of a member');
reset role;
select extensions.ok(not has_table_privilege('authenticated','iam.membership_suspension_snapshots','select'),'G5 the snapshot table is not readable by authenticated');
select * from extensions.finish();
rollback;
