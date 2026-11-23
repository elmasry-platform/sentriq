-- Company reactivation restores exactly what its suspension took down:
-- envelopes and the decisions, action grants and profiles sourced from them.
-- Role assignment history is immutable, so sourced role assignments stay
-- revoked (fail-closed) and every skip is audited.
begin;
select extensions.plan(48);

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
select extensions.is(api.revoke_delegation('71000000-0000-0000-0000-000000000001',(select id from restore_envs where k='D3'),'Withdraw before suspension'),1,'revoking the spare envelope removes exactly it');
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

select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='D3')),'revoked'::text,'spare envelope is revoked before the company suspension');
update iam.memberships set status='suspended' where id='72000000-0000-0000-0000-000000000005';
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='D5')),'suspended'::text,'membership suspension suspends its envelope independently');
select extensions.ok(not (select suspended_by_tenant from iam.delegation_envelopes where id=(select id from restore_envs where k='D5')),'independent suspension carries no company marker');

select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Company pause');
reset role;
select extensions.is((select count(*)::integer from iam.delegation_envelopes where tenant_id='71000000-0000-0000-0000-000000000001' and status='suspended'),5,'company suspension suspends every active envelope alongside the already suspended one');
select extensions.is((select count(*)::integer from iam.delegation_envelopes where tenant_id='71000000-0000-0000-0000-000000000001' and suspended_by_tenant),4,'exactly the envelopes the suspension took down are marked');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='D3')),'revoked'::text,'revoked envelope is untouched by the suspension');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='CT')),'active'::text,'other company envelope is untouched by the suspension');
select extensions.ok((select status='suspended' and suspended_by_tenant from iam.member_permission_decisions where id=(select id from restore_envs where k='dec1')),'sourced decision is suspended and marked with the envelope');
select extensions.ok((select status='suspended' and suspended_by_tenant from iam.permission_action_grants where tenant_id='71000000-0000-0000-0000-000000000001' and source_delegation_id=(select id from restore_envs where k='P')),'sourced action grant is suspended and marked with the envelope');
select extensions.ok((select not is_current and suspended_by_tenant from iam.membership_permission_profiles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000003'),'sourced profile is deactivated and marked with the envelope');
select extensions.ok((select not is_current and suspended_by_tenant from iam.membership_permission_profiles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000008'),'second sourced profile is deactivated and marked with the envelope');
select extensions.ok((select revoked_at is not null and revoke_reason='Source delegation suspended by company suspension' from iam.membership_roles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000003'),'sourced role assignment is revoked and named as company-suspension takedown');
select extensions.ok((select status='suspended' and suspended_by_tenant from iam.member_permission_decisions where id=(select id from restore_envs where k='dec2')),'short-window sourced decision is suspended and marked');
update iam.delegation_envelopes set starts_at=now()-interval '30 minutes',ends_at=now()-interval '1 second' where id=(select id from restore_envs where k='D4');
update iam.member_permission_decisions set starts_at=now()-interval '30 minutes',ends_at=now()-interval '1 second' where id=(select id from restore_envs where k='dec2');
-- An engagement ending while the company is down is an independent cause.
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000002',true);
update hse.person_engagements set status='ended',ends_at=now() where id='74000000-0000-0000-0000-000000000001';
select extensions.ok((select status='revoked' and not suspended_by_tenant from iam.delegation_envelopes where id=(select id from restore_envs where k='E1')),'engagement end during company suspension revokes the envelope');
-- A competing current profile appears while the company is down.
insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,source,assigned_by)
 values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000008','employee','61000000-0000-0000-0000-000000007101','62000000-0000-0000-0000-000000007101','explicit_application','70000000-0000-0000-0000-000000000002');

select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Company back');
reset role;
select extensions.ok((select status='active' and not suspended_by_tenant from iam.delegation_envelopes where id=(select id from restore_envs where k='P')),'parent envelope returns with the company');
select extensions.ok((select status='active' and not suspended_by_tenant from iam.delegation_envelopes where id=(select id from restore_envs where k='C')),'child envelope returns with the company');
select extensions.ok((select status='suspended' and not suspended_by_tenant from iam.delegation_envelopes where id=(select id from restore_envs where k='D4')),'envelope whose window ended during the suspension is not restored');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='D5')),'suspended'::text,'independently suspended envelope stays down');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='D3')),'revoked'::text,'revoked envelope stays revoked');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='CT')),'active'::text,'control envelope still active after reactivation');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='E1')),'revoked'::text,'engagement-ended envelope is not laundered back by reactivation');
select extensions.ok((select status='active' and not suspended_by_tenant from iam.member_permission_decisions where id=(select id from restore_envs where k='dec1')),'sourced decision returns with the envelope');
select extensions.ok((select status='active' and not suspended_by_tenant from iam.permission_action_grants where tenant_id='71000000-0000-0000-0000-000000000001' and source_delegation_id=(select id from restore_envs where k='P')),'sourced action grant returns with the envelope');
select extensions.ok((select is_current and not suspended_by_tenant from iam.membership_permission_profiles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000003'),'sourced profile is current again with the envelope');
select extensions.ok((select revoked_at is not null from iam.membership_roles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000003'),'fail-closed: revoked role assignment history is immutable and stays revoked');
select extensions.ok((select status='suspended' and not suspended_by_tenant from iam.member_permission_decisions where id=(select id from restore_envs where k='dec2')),'sourced decision whose window ended during the suspension is not restored');
select extensions.ok((select not is_current and not suspended_by_tenant from iam.membership_permission_profiles where tenant_id='71000000-0000-0000-0000-000000000001' and membership_id='72000000-0000-0000-0000-000000000008' and source_delegation_id is not null),'conflicted sourced profile stays deactivated');
select extensions.is((select count(*)::integer from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation.restored'),2,'one audit row per restored envelope');
select extensions.is((select count(*)::integer from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation.restored' and summary->>'cause'='tenant_reactivation'),2,'restore audit rows name the cause');
select extensions.is((select count(*)::integer from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation_source.restored'),3,'one audit row per restored sourced effect');
select extensions.ok(exists(select 1 from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='role_assignment_history_immutable'),'skipped role assignment restore is audited');
select extensions.ok(exists(select 1 from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='validity_window_ended'),'expired sourced decision skip is audited');
select extensions.ok(exists(select 1 from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation_source.restore_skipped' and summary->>'reason'='conflicting_current_profile'),'conflicted profile skip is audited');
select extensions.ok(private.people_delegation_allows('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000002','role_assignment',null,null,null),'restored envelope is usable again');
select extensions.throws_ok($$update iam.delegation_envelopes set status='active' where id=(select id from restore_envs where k='D4')$$,'23514','delegation_cannot_be_reactivated','expired envelope still cannot be reactivated by hand');
select extensions.throws_ok($$update iam.delegation_envelopes set status='active' where id=(select id from restore_envs where k='D5')$$,'23514','delegation_cannot_be_reactivated','independently suspended envelope still cannot be reactivated by hand');

select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','suspended','Second company pause');
reset role;
select extensions.is((select count(*)::integer from iam.delegation_envelopes where tenant_id='71000000-0000-0000-0000-000000000001' and suspended_by_tenant),2,'second suspension marks the two active envelopes');
select extensions.ok((select status='suspended' and suspended_by_tenant from iam.member_permission_decisions where id=(select id from restore_envs where k='dec1')),'second suspension marks the sourced decision again');
select extensions.throws_ok($$update iam.delegation_envelopes set status='active',suspended_by_tenant=false where id=(select id from restore_envs where k='P')$$,'23514','delegation_cannot_be_reactivated','marked envelope cannot be restored outside the tenant lifecycle path');
update iam.memberships set status='suspended' where id='72000000-0000-0000-0000-000000000002';
select extensions.ok(not exists(select 1 from iam.delegation_envelopes where tenant_id='71000000-0000-0000-0000-000000000001' and suspended_by_tenant),'membership suspension takes over the cause on both marked envelopes');
select extensions.ok(not (select suspended_by_tenant from iam.member_permission_decisions where id=(select id from restore_envs where k='dec1')),'membership suspension takes over the cause on the sourced decision');
select set_config('request.jwt.claim.sub','70000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select api.platform_set_tenant_status('71000000-0000-0000-0000-000000000001','active','Second company return');
reset role;
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='P')),'suspended'::text,'envelope with an independent membership cause is not restored by company reactivation');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='C')),'suspended'::text,'child envelope under the same membership cause is not restored either');
select extensions.is((select status from iam.member_permission_decisions where id=(select id from restore_envs where k='dec1')),'suspended'::text,'sourced decision under the membership cause is not restored either');
select extensions.is((select count(*)::integer from audit.events where tenant_id='71000000-0000-0000-0000-000000000001' and action_key='iam.delegation.restored'),2,'no new restore audit rows when nothing is restored');
select extensions.is((select status from iam.delegation_envelopes where id=(select id from restore_envs where k='CT')),'active'::text,'control envelope remains active throughout');
select extensions.throws_ok($$insert into iam.delegation_envelopes(tenant_id,grantor_membership_id,delegate_membership_id,level,allowed_capabilities,status,suspended_by_tenant,created_by) values('71000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000001','72000000-0000-0000-0000-000000000003','tenant',array['role_assignment'],'suspended',true,'70000000-0000-0000-0000-000000000002')$$,'23514','delegation_suspension_origin_forced','the company-suspension marker cannot be inserted directly');

select * from extensions.finish();
rollback;
