-- 051 guard fixes: (1) operator-origin decision no longer blocks member suspension; (2) operator can revoke a superadmin assignment. Needs 048-050 and 051.
begin;
select extensions.plan(27);
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
insert into iam.member_permission_decisions(id,tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason,protected_origin)
 values('c7000000-0000-0000-0000-000000000001','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000001','Operator grant',true);
select set_config('sentriq.migration_runner','off',true);
-- P1 operator suspends the member that holds the protected decision
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select extensions.lives_ok($q$select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','suspended','Probe pause')$q$,'T01 operator can suspend a member who holds an operator-origin decision');
reset role;
select extensions.is((select status||'/'||protected_origin::text from iam.member_permission_decisions where id='c7000000-0000-0000-0000-000000000001'),'suspended/true','T02 the protected decision is suspended and still protected');
select extensions.is((select status from iam.memberships where id='c2000000-0000-0000-0000-000000000010'),'suspended','T03 the member is suspended');
-- reactivation by operator does not bring the protected decision back (current behavior, needs the decision actor setting)
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000010','active','Probe return');
reset role;
select extensions.is((select status from iam.member_permission_decisions where id='c7000000-0000-0000-0000-000000000001'),'suspended','T04 reactivation leaves the protected decision suspended (needs an operator decision action)');
-- the setting alone does not unlock direct writes (superuser session, request actor is a company superadmin)
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
select set_config('sentriq.member_lifecycle_suspend','on',true);
select extensions.throws_ok($q$update iam.member_permission_decisions set status='active' where id='c7000000-0000-0000-0000-000000000001'$q$,'42501','operator_decision_requires_operator','T05 direct reactivation of a protected decision is still refused even with the setting on');
select extensions.throws_ok($q$update iam.member_permission_decisions set can_write=true where id='c7000000-0000-0000-0000-000000000001'$q$,'42501','operator_decision_requires_operator','T06 direct edit of a protected decision is still refused with the setting on');
select set_config('sentriq.member_lifecycle_suspend','off',true);
-- an unprotected decision is still suspended and restored as before (control)
select extensions.is((select count(*) from iam.member_permission_decisions where tenant_id='c1000000-0000-0000-0000-00000000000a' and membership_id='c2000000-0000-0000-0000-000000000004' and status='active')::int,1,'T07 control: delegate decision is active before its member is suspended');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','suspended','Probe pause 2');
reset role;
select extensions.is((select count(*) from iam.member_permission_decisions where tenant_id='c1000000-0000-0000-0000-00000000000a' and membership_id='c2000000-0000-0000-0000-000000000004' and status='active')::int,0,'T08 control: unprotected decision is suspended with its member');
-- R: operator revoke path
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a','c6000000-0000-0000-0000-000000000001','Company SA tries SB')$q$,'42501','superadmin_target_requires_operator','T09 company superadmin still cannot revoke another superadmin assignment');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000013',true);
set local role authenticated;
select extensions.throws_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a',(select id from mx where k='A1'),'Other tenant employee')$q$,'42501',null,'T10 a user with no authority in the tenant still cannot revoke');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select extensions.lives_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a','c6000000-0000-0000-0000-000000000001','Operator revokes superadmin assignment')$q$,'T11 operator can revoke a superadmin single assignment that has no scope rows');
reset role;
select extensions.is((select (revoked_at is not null)::text||'/'||(select count(*) from audit.events where action_key='iam.membership_role.revoked' and record_id='c6000000-0000-0000-0000-000000000001' and summary->>'by_operator'='true')::text from iam.membership_roles where id='c6000000-0000-0000-0000-000000000001'),'true/1','T12 the assignment is revoked and the audit row says by_operator');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select extensions.lives_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a',(select id from mx where k='A2'),'Operator revokes site assignment')$q$,'T13 operator can revoke a site-scoped assignment');
select extensions.throws_ok($q$select api.revoke_role_assignment('c1000000-0000-0000-0000-00000000000a','c6000000-0000-0000-0000-0000000000ff','Operator unknown')$q$,'22023','invalid_assignment_revocation','T14 unknown assignment is still invalid for the operator');
reset role;
-- nested (depth 2) probes: the cascade allowance is narrow
reset role;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(id,tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason,protected_origin)
 values('c7000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000009','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000001','Operator grant 2',true);
select set_config('sentriq.migration_runner','off',true);
create temporary table kick(id int);
create function pg_temp.kick_fn() returns trigger language plpgsql as $f$ begin execute current_setting('probe.sql'); return new; end $f$;
create trigger kick_t after insert on pg_temp.kick for each row execute function pg_temp.kick_fn();
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
select set_config('sentriq.member_lifecycle_suspend','off',true);
select set_config('probe.sql',$p$update iam.member_permission_decisions set status='suspended' where id='c7000000-0000-0000-0000-000000000003'$p$,false);
select extensions.throws_ok($q$insert into pg_temp.kick values(1)$q$,'42501','operator_decision_requires_operator','T15 nested suspend of a protected decision is refused when the cascade setting is off');
select set_config('sentriq.member_lifecycle_suspend','on',true);
select set_config('probe.sql',$p$update iam.member_permission_decisions set can_write=true where id='c7000000-0000-0000-0000-000000000003'$p$,false);
select extensions.throws_ok($q$insert into pg_temp.kick values(2)$q$,'42501','operator_decision_requires_operator','T16 nested edit of other columns is refused even with the cascade setting on');
select set_config('probe.sql',$p$update iam.member_permission_decisions set status='suspended' where id='c7000000-0000-0000-0000-000000000003'$p$,false);
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
select extensions.throws_ok($q$insert into pg_temp.kick values(5)$q$,'42501','operator_decision_requires_operator','T19 the nested suspend is refused when the signed-in user is not a platform operator, even with the setting on');
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000001',true);
select set_config('probe.sql',$p$update iam.member_permission_decisions set status='suspended',reason='changed by probe' where id='c7000000-0000-0000-0000-000000000003'$p$,false);
select extensions.throws_ok($q$insert into pg_temp.kick values(6)$q$,'42501','operator_decision_requires_operator','T20 an operator nested suspend that also changes reason is refused (whole row must match except status and updated_at)');
select set_config('probe.sql',$p$update iam.member_permission_decisions set status='suspended' where id='c7000000-0000-0000-0000-000000000003'$p$,false);
select extensions.lives_ok($q$insert into pg_temp.kick values(3)$q$,'T17 nested active to suspended with the setting on, signed-in operator, no other change: the one allowed change');
select set_config('probe.sql',$p$update iam.member_permission_decisions set status='active' where id='c7000000-0000-0000-0000-000000000001'$p$,false);
select extensions.throws_ok($q$insert into pg_temp.kick values(4)$q$,'42501','operator_decision_requires_operator','T18 nested suspended to active of a protected decision is refused even with the setting on');
select set_config('sentriq.member_lifecycle_suspend','off',true);
reset role;
-- F-A: company paths behave as before 051 (service_role api.set_membership_status, actor passed as a parameter)
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(id,tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason,protected_origin) values
 ('c7000000-0000-0000-0000-000000000004','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','hse.dashboard.read','allow','tenant',true,false,'c0000000-0000-0000-0000-000000000001','Operator allow',true),
 ('c7000000-0000-0000-0000-000000000005','c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','hse.dashboard.read','deny','tenant',false,false,'c0000000-0000-0000-0000-000000000001','Operator deny',true);
select set_config('sentriq.migration_runner','off',true);
select set_config('request.jwt.claim.sub','',true);
select set_config('request.jwt.claim.role','service_role',true);
select extensions.throws_ok($q$select api.set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','suspended','c0000000-0000-0000-0000-000000000002','Company suspend probe')$q$,'42501','operator_decision_requires_operator','T21 company superadmin suspending a member with a protected ALLOW decision is refused (as before 051)');
select extensions.throws_ok($q$select api.set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','suspended','c0000000-0000-0000-0000-000000000002','Company suspend probe')$q$,'42501','operator_decision_requires_operator','T22 company superadmin suspending a member with a protected DENY decision is refused (as before 051)');
select extensions.throws_ok($q$select api.set_membership_status('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','suspended','c0000000-0000-0000-0000-000000000004','Delegated admin probe')$q$,'42501','company_superadmin_required_for_membership_status','T23 a delegated company admin cannot suspend a member through that function at all');
select set_config('request.jwt.claim.role','authenticated',true);
select extensions.is((select string_agg(m.status||'/'||d.status,',' order by d.id) from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where d.id in ('c7000000-0000-0000-0000-000000000004','c7000000-0000-0000-0000-000000000005')),'active/active,active/active','T24 after the refusals both members are still active and both protected decisions are still active');
-- F-C: setting pre-set on, authenticated company superadmin, direct RPCs on a protected decision
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
select set_config('sentriq.member_lifecycle_suspend','on',true);
set local role authenticated;
select extensions.throws_ok($q$select api.clear_member_permission_decision('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000007','hse.dashboard.read','Clear probe')$q$,'42501','operator_decision_requires_operator','T25 company superadmin cannot clear a protected decision through the RPC with the setting on');
select extensions.throws_ok($q$select api.set_member_permission_decision('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000008','hse.dashboard.read','allow','tenant',null,null,null,null,true,false,null,null,'Override probe')$q$,'42501','operator_decision_requires_operator','T26 company superadmin cannot replace a protected deny through the RPC with the setting on');
reset role;
select set_config('sentriq.member_lifecycle_suspend','off',true);
select extensions.is((select string_agg(status||'/'||decision,',' order by id) from iam.member_permission_decisions where id in ('c7000000-0000-0000-0000-000000000004','c7000000-0000-0000-0000-000000000005')),'active/allow,active/deny','T27 both protected decisions are unchanged');
select * from extensions.finish();
rollback;
