-- Company reactivation restores exactly what its suspension took down:
-- envelopes and the decisions, action grants and profiles sourced from them.
-- Tenant-caused sourced role takedowns restore; independent revocation stays terminal.
begin;
select extensions.plan(54);

insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('70000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','delegation-restore-'||i||'@example.test',now(),now(),now()
from generate_series(1,8) i;
select private.bootstrap_platform_owner('70000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values
 ('71000000-0000-0000-0000-000000000001','Restore A','70000000-0000-0000-0000-000000000001'),
 ('71000000-0000-0000-0000-000000000002','Restore B','70000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,email) values
 ('72000000-0000-0000-0000-000000000001','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000002','company_superadmin','delegation-restore-2@example.test'),
 ('72000000-0000-0000-0000-000000000002','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000003','company_admin','delegation-restore-3@example.test'),
 ('72000000-0000-0000-0000-000000000003','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000004','employee','delegation-restore-4@example.test'),
 ('72000000-0000-0000-0000-000000000005','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000005','employee','delegation-restore-5@example.test'),
 ('72000000-0000-0000-0000-000000000006','71000000-0000-0000-0000-000000000002','70000000-0000-0000-0000-000000000006','company_superadmin','delegation-restore-6@example.test'),
 ('72000000-0000-0000-0000-000000000007','71000000-0000-0000-0000-000000000002','70000000-0000-0000-0000-000000000007','employee','delegation-restore-7@example.test'),
 ('72000000-0000-0000-0000-000000000008','71000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000008','employee','delegation-restore-8@example.test');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select t,'hse',now()-interval '1 day',now()+interval '1 day','70000000-0000-0000-0000-000000000001','Restore fixture entitlement','complimentary'
from unnest(array['71000000-0000-0000-0000-000000000001'::uuid,'71000000-0000-0000-0000-000000000002'::uuid]) t;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
set local role authenticated;
insert into hse.people(id,tenant_id,display_name,person_kind,status,membership_id,created_by) values
 ('73000000-0000-0000-0000-000000000001','71000000-0000-0000-0000-000000000001','Restore engaged worker','employee','active','72000000-0000-0000-0000-000000000008','70000000-0000-0000-0000-000000000002');
insert into hse.person_engagements(id,tenant_id,person_id,engagement_type,starts_at,status,created_by) values
 ('74000000-0000-0000-0000-000000000001','71000000-0000-0000-0000-000000000001','73000000-0000-0000-0000-000000000001','employee',now()-interval '10 days','active','70000000-0000-0000-0000-000000000002');
reset role;
insert into iam.roles(id,tenant_id,role_key,label,role_family,created_by) values
 ('60000000-0000-0000-0000-000000007101','71000000-0000-0000-0000-000000000001','restore_employee','Restore Employee','employee','70000000-0000-0000-0000-000000000001');
insert into iam.permission_profiles(id,tenant_id,role_family,profile_name,created_by) values
 ('61000000-0000-0000-0000-000000007101','71000000-0000-0000-0000-000000000001','employee','Restore Profile','70000000-0000-0000-0000-000000000001');
insert into iam.permission_profile_versions(id,tenant_id,profile_id,version_no,created_by) values
 ('62000000-0000-0000-0000-000000007101','71000000-0000-0000-0000-000000000001','61000000-0000-0000-0000-000000007101',1,'70000000-0000-0000-0000-000000000001');
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.publish_role_version('71000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000007101','[{"permission_key":"view_all","scope_kind":"tenant","can_read":true,"can_write":false}]'::jsonb,'Restore role fixture');
reset role;

insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason)
 values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000002','view_all','allow','tenant',true,'70000000-0000-0000-0000-000000000002','Admin use authority within envelope'),
       ('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000002','hse.dashboard.read','allow','tenant',true,'70000000-0000-0000-0000-000000000002','Admin use authority for the short-window fixture');

create temporary table restore_envs(k text primary key, id uuid not null) on commit drop;
grant insert,select on table pg_temp.restore_envs to authenticated;

select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
set local role authenticated;
insert into restore_envs(k,id) select 'P',api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000002','tenant',null,null,array['role_assignment','direct_permission_decision'],now(),null,'Restore parent envelope');
insert into restore_envs(k,id) select 'D3',api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','tenant',null,null,array['direct_permission_decision'],now(),null,'Spare envelope revoked before suspension');
insert into restore_envs(k,id) select 'D4',api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000002','tenant',null,null,array['scope_management'],now(),now()+interval '1 hour','Envelope expiring during suspension');
insert into restore_envs(k,id) select 'D5',api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000005','tenant',null,null,array['scope_management'],now(),null,'Individually suspended envelope');
insert into restore_envs(k,id) select 'E1',api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000008','tenant',null,null,array['scope_management'],now(),null,'Engaged worker envelope');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000003',true);
insert into restore_envs(k,id) select 'C',api.create_delegation('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','tenant',null,null,array['role_assignment'],now(),null,'Child envelope inside parent');
insert into restore_envs(k,id) select 'dec1',api.set_member_permission_decision('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','view_all','allow','tenant',null,null,null,null,true,false,null,null,'Sourced decision fixture');
insert into restore_envs(k,id) select 'dec2',api.set_member_permission_decision('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','hse.dashboard.read','allow','tenant',null,null,null,null,true,false,now()+interval '1 hour',null,'Short window sourced decision');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000006',true);
insert into restore_envs(k,id) select 'CT',api.create_delegation('71000000-0000-0000-0000-000000000002','72000000-0000-0000-0000-000000000007','tenant',null,null,array['role_assignment'],now(),null,'Control envelope in another company');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
select api.revoke_delegation('71000000-0000-0000-0000-000000000001',(select id from restore_envs where k='D3'),'Withdraw before suspension');
reset role;

insert into iam.permission_action_grants(tenant_id,membership_id,permission_key,action_key,decision,scope_kind,starts_at,created_by,reason,source_delegation_id)
 values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','view_all','read','allow','tenant',now(),'70000000-0000-0000-0000-000000000003','Sourced grant fixture',(select id from restore_envs where k='P'));
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select api.set_default_permission_profile('71000000-0000-0000-0000-000000000001','employee','Restore Profile',
 '[{"permission_key":"view_all","scope_kind":"tenant","can_read":true}]'::jsonb,
 'selected_existing_users',array['72000000-0000-0000-0000-000000000003'::uuid,'72000000-0000-0000-0000-000000000008'::uuid],
 'Sourced profile fixture',(select id from restore_envs where k='P'));
select api.assign_membership_role('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','60000000-0000-0000-0000-000000007101',(select id from iam.role_versions where tenant_id='71000000-0000-0000-0000-000000000001' and role_id='60000000-0000-0000-0000-000000007101' and status='published'),null,null,now(),null,'Sourced role assignment fixture');
reset role;


create temporary table role_fixture(k text primary key,id uuid);
insert into role_fixture select 'main',id from iam.membership_roles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000003';
grant select on role_fixture to authenticated;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'tenant pause marks exactly its role takedown');
select extensions.throws_ok($attack$update iam.membership_roles set revoked_at=null,revoked_by=null,revoke_reason=null,suspended_by_tenant=false where id=(select id from role_fixture where k='main')$attack$,'23514','functional role assignment history is immutable','manual marked restore is blocked');
select set_config('iam.delegation_tenant_restore','on',true);
select extensions.throws_ok($attack$update iam.membership_roles set revoked_at=null,revoked_by=null,revoke_reason=null,suspended_by_tenant=false where id=(select id from role_fixture where k='main')$attack$,'23514','functional role assignment history is immutable','forged GUC alone cannot un-revoke a role');
select set_config('iam.delegation_tenant_restore','off',true);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'company return restores original role row');
select extensions.is((select count(*) from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restored')::integer,1,'one role restore audit');
select extensions.ok(exists(select 1 from audit.events where record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restored' and actor_user_id='70000000-0000-0000-0000-000000000001' and summary->>'cause'='tenant_reactivation'),'role restore audit binds actor and cause');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'repeat cycle 1 restores same assignment');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'repeat cycle 2 restores same assignment');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'repeat cycle 3 restores same assignment');
select extensions.is((select count(*) from iam.membership_roles where id=(select id from role_fixture where k='main'))::integer,1,'repeat cycles do not create role duplicates');
select extensions.is((select count(*) from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restored')::integer,4,'each restore cycle audited once');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($attack$update iam.membership_roles set suspended_by_tenant=true where id=(select id from role_fixture where k='main')$attack$,'23514','role_suspension_origin_forced','authenticated manager cannot forge role origin');
reset role;
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select extensions.throws_ok($attack$update iam.membership_roles set revoked_at=now(),revoked_by=granted_by,revoke_reason='fake',suspended_by_tenant=true where id=(select id from role_fixture where k='main')$attack$,'23514','role_suspension_origin_forced','cannot forge takedown provenance');
update iam.membership_roles set revoked_at=now(),revoked_by=granted_by,revoke_reason='Source delegation suspended by company suspension' where id=(select id from role_fixture where k='main');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'historical reason text does not create restore authority');
select extensions.is((select count(*) from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restored')::integer,0,'no restoration audit for pre-revoked role');
select extensions.throws_ok($attack$update iam.membership_roles set revoked_at=null,revoked_by=null,revoke_reason=null where id=(select id from role_fixture where k='main')$attack$,'23514','functional role assignment history is immutable','independent revocation is still terminal');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select extensions.throws_ok($attack$update iam.membership_roles set granted_by='70000000-0000-0000-0000-000000000001' where id=(select id from role_fixture where k='main')$attack$,'23514','functional role assignment history is immutable','marked history still pins granted_by');
select extensions.throws_ok($attack$update iam.membership_roles set starts_at=now()-interval '1 day' where id=(select id from role_fixture where k='main')$attack$,'23514','role_assignment_identity_is_immutable','marked history still pins starts_at');
select extensions.throws_ok($attack$update iam.membership_roles set ends_at=now()+interval '1 day' where id=(select id from role_fixture where k='main')$attack$,'23514','role_assignment_identity_is_immutable','marked history still pins ends_at');
select extensions.throws_ok($attack$update iam.membership_roles set source_delegation_id=(select id from restore_envs where k='C') where id=(select id from role_fixture where k='main')$attack$,'23514','assignment_source_is_immutable','marked history still pins source_delegation_id');
update iam.membership_roles set suspended_by_tenant=false where id=(select id from role_fixture where k='main');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'independent takeover clearing marker prevents restore');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.memberships set status='suspended' where id='72000000-0000-0000-0000-000000000003';
select extensions.ok((select not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target lifecycle clears role origin: suspended');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target lifecycle change stays down');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.memberships set status='ended' where id='72000000-0000-0000-0000-000000000003';
select extensions.ok((select not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target lifecycle clears role origin: ended');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target lifecycle change stays down');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.memberships set member_role='company_admin' where id='72000000-0000-0000-0000-000000000003';
select extensions.ok((select not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target lifecycle clears role origin: company_admin');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target lifecycle change stays down');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.memberships set status='suspended' where id='72000000-0000-0000-0000-000000000003';
update iam.memberships set status='active' where id='72000000-0000-0000-0000-000000000003';
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'target suspension then return does not launder role history');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.memberships set status='suspended' where id='72000000-0000-0000-0000-000000000002';
select extensions.ok((select not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'source membership takeover clears role origin');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'source membership cause stays down');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
delete from role_fixture;
insert into role_fixture select 'main',gen_random_uuid();
update iam.membership_roles set revoked_at=now(),revoked_by=granted_by,revoke_reason='Replace with expired fixture';
insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,starts_at,ends_at,granted_by,source_delegation_id) select (select id from role_fixture where k='main'),tenant_id,membership_id,role_id,role_version_id,now()-interval '2 days',now()-interval '1 day',granted_by,source_delegation_id from iam.membership_roles limit 1;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'expired role is not restored');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='validity_window_ended'),'skip audited: validity_window_ended');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.delegation_envelopes set starts_at=now()-interval '2 days',ends_at=now()-interval '1 day' where id=(select id from restore_envs where k='P');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'expired source envelope prevents role restore');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='envelope_not_restored'),'skip audited: envelope_not_restored');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason) values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000001','role_assignment',false,false,'70000000-0000-0000-0000-000000000001','Tighten during company pause');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'tightened role_assignment limit blocks restoration');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='capability_limit_tightened'),'skip audited: capability_limit_tightened');
delete from iam.superadmin_capability_limits where tenant_id='71000000-0000-0000-0000-000000000001';
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'loosening a limit later does not queue a restore');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason) values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000001','view_all',false,false,'70000000-0000-0000-0000-000000000001','Tighten during company pause');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'tightened view_all limit blocks restoration');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='capability_limit_tightened'),'skip audited: capability_limit_tightened');
delete from iam.superadmin_capability_limits where tenant_id='71000000-0000-0000-0000-000000000001';
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'loosening a limit later does not queue a restore');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
update iam.roles set active=false where id='60000000-0000-0000-0000-000000007101';
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'inactive role is not restored');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='role_not_assignable'),'skip audited: role_not_assignable');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,starts_at,granted_by) select tenant_id,membership_id,role_id,role_version_id,starts_at,granted_by from iam.membership_roles where id=(select id from role_fixture where k='main');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'conflicting active assignment blocks old role restoration');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='conflicting_current_role'),'skip audited: conflicting_current_role');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,starts_at,granted_by,source_delegation_id) select tenant_id,'72000000-0000-0000-0000-000000000008',role_id,role_version_id,starts_at,granted_by,source_delegation_id from iam.membership_roles where id=(select id from role_fixture where k='main');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
update hse.person_engagements set status='ended',ends_at=now() where id='74000000-0000-0000-0000-000000000001';
select extensions.ok((select not suspended_by_tenant from iam.membership_roles where membership_id='72000000-0000-0000-0000-000000000008'),'target engagement end clears marker independently of source envelope');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null from iam.membership_roles where membership_id='72000000-0000-0000-0000-000000000008'),'target engagement ended role stays down');
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'unrelated role under same envelope still returns');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select private.revoke_delegation_tree('71000000-0000-0000-0000-000000000001',(select id from restore_envs where k='P'),'70000000-0000-0000-0000-000000000001','Independent revoke during pause',false);
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'explicit envelope revoke during pause remains terminal');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
update iam.membership_roles set revoked_at=now(),revoked_by=granted_by,revoke_reason='Old independent grant' where id=(select id from role_fixture where k='main');
select extensions.throws_ok($attack$insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,starts_at,granted_by,source_delegation_id,revoked_at,revoked_by,revoke_reason,suspended_by_tenant) select tenant_id,membership_id,role_id,role_version_id,starts_at,granted_by,source_delegation_id,revoked_at,revoked_by,revoke_reason,true from iam.membership_roles where id=(select id from role_fixture where k='main')$attack$,'23514','role_suspension_origin_forced','marker cannot be supplied on insert');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
savepoint scenario;
insert into core.org_units(id,tenant_id,name) values('75000000-0000-0000-0000-000000000001','71000000-0000-0000-0000-000000000001','Role restore unit');
insert into core.sites(id,tenant_id,org_unit_id,name,code) values('76000000-0000-0000-0000-000000000001','71000000-0000-0000-0000-000000000001','75000000-0000-0000-0000-000000000001','Role restore site','RESTORE');
insert into iam.roles(id,tenant_id,role_key,label,role_family,created_by) values('60000000-0000-0000-0000-000000007102','71000000-0000-0000-0000-000000000001','restore_scope','Restore Scoped Role','employee','70000000-0000-0000-0000-000000000002');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.publish_role_version('71000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000007102','[{"permission_key":"view_all","scope_kind":"site","can_read":true,"can_write":false},{"permission_key":"view_all","scope_kind":"org_unit","can_read":true,"can_write":false}]'::jsonb,'Scoped restore fixture');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000003',true);
delete from role_fixture;
insert into role_fixture select 'main',gen_random_uuid();
insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,granted_by,source_delegation_id) select (select id from role_fixture where k='main'),'71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','60000000-0000-0000-0000-000000007102',id,'70000000-0000-0000-0000-000000000003',(select id from restore_envs where k='P') from iam.role_versions where role_id='60000000-0000-0000-0000-000000007102';
insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by) values('71000000-0000-0000-0000-000000000001',(select id from role_fixture where k='main'),'76000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000003');
insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by) values('71000000-0000-0000-0000-000000000001',(select id from role_fixture where k='main'),'75000000-0000-0000-0000-000000000001','70000000-0000-0000-0000-000000000003');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'tenant pause restores role with unchanged site and org bindings');
select extensions.ok((select revoked_at is null from iam.membership_role_sites where membership_role_id=(select id from role_fixture where k='main')),'site binding remains unrevoked');
select extensions.ok((select revoked_at is null from iam.membership_role_org_units where membership_role_id=(select id from role_fixture where k='main')),'org binding remains unrevoked');
update iam.membership_role_sites set revoked_at=now(),revoked_by=granted_by,revoke_reason='Independent site revocation' where membership_role_id=(select id from role_fixture where k='main');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Pause for role restore test');
reset role;
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Return for role restore test');
reset role;
select extensions.ok((select revoked_at is not null and not suspended_by_tenant from iam.membership_roles where id=(select id from role_fixture where k='main')),'independent scope revocation blocks full role restoration');
select extensions.ok(exists(select 1 from audit.events where record_type='iam.membership_roles' and record_id=(select id from role_fixture where k='main') and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='scope_binding_ended'),'skip audited: scope_binding_ended');
select extensions._get('curr_test') as tap_n, extensions.num_failed() as tap_failed \gset
rollback to savepoint scenario;
select extensions._set('curr_test',:tap_n);
select extensions._set('failed',:tap_failed);
release savepoint scenario;
select * from extensions.finish();
rollback;
