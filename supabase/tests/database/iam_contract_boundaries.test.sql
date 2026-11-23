-- Independent regression tests for the reviewed privilege boundaries.
begin;
select extensions.plan(34);
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('90000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','iam-contract-'||i||'@example.test',now(),now(),now()
from generate_series(1,8) i;
select private.bootstrap_platform_owner('90000000-0000-0000-0000-000000000001');
insert into iam.platform_operators(user_id,operator_role,created_by)
values('90000000-0000-0000-0000-000000000008','subowner','90000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values
 ('91000000-0000-0000-0000-000000000001','Contract A','90000000-0000-0000-0000-000000000001'),
 ('91000000-0000-0000-0000-000000000002','Contract B','90000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,email)
select ('92000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'91000000-0000-0000-0000-000000000001',
 ('90000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,
 case when i in (2,3) then 'company_superadmin' when i=4 then 'company_admin' else 'employee' end,
 'iam-contract-'||i||'@example.test' from generate_series(2,7) i;
select extensions.is((select count(*)::integer from iam.memberships where tenant_id='91000000-0000-0000-0000-000000000001' and member_role='company_superadmin'),2,'two active Superadmins coexist');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select '91000000-0000-0000-0000-000000000001',m,now()-interval '1 day',now()+interval '1 day','90000000-0000-0000-0000-000000000001','Contract fixture entitlement','complimentary'
from unnest(array['hse','operations','core']) m;
insert into iam.permission_catalog(permission_key,module_key,label,supported_actions) values
 ('operations.contract.read','operations','Contract Operations access',array['read','approve','export']),
 ('hse.contract.task','hse','Contract task access',array['read','write']);
-- The independent evaluator unit fixture has no HSE business task rows.
-- Disable target FK trigger only for privileged fixture setup, then restore.
alter table iam.task_assignments disable trigger task_assignment_target_guard;
insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by)
select '91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000005','inspection',
 ('93000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'90000000-0000-0000-0000-000000000002' from generate_series(1,2) i;
alter table iam.task_assignments enable trigger task_assignment_target_guard;
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,task_kind,task_id,can_read,granted_by,reason)
values('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000005','hse.contract.task','allow','assigned_task','inspection','93000000-0000-0000-0000-000000000001',true,'90000000-0000-0000-0000-000000000002','Only task one allowed');
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason)
values('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000005','operations.contract.read','allow','tenant',true,'90000000-0000-0000-0000-000000000002','Operations independent of HSE');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000005',true);
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','hse.contract.task','read',null,null,'inspection','93000000-0000-0000-0000-000000000001'),'exact task grant allows task one');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','hse.contract.task','read',null,null,'inspection','93000000-0000-0000-0000-000000000002'),'task one grant cannot leak to another assigned task');
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','read'),'Operations catalog grant works');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','approve'),'read does not imply approval');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','export'),'read does not imply export');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000002','operations.contract.read','read'),'known other-company ID does not confer membership');
reset role;
update core.entitlement_grants set status='suspended' where tenant_id='91000000-0000-0000-0000-000000000001' and module_key='hse';
set local role authenticated;
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','read'),'Operations still works with HSE suspended');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','hse.contract.task','read',null,null,'inspection','93000000-0000-0000-0000-000000000001'),'HSE disabled denies HSE task');
reset role;
update core.entitlement_grants set status='active' where tenant_id='91000000-0000-0000-0000-000000000001' and module_key='hse';
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.create_delegation('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000004','tenant',null,null,array['direct_permission_decision'],now(),now()+interval '1 hour','Contract bounded decision authority');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000004',true);
select extensions.throws_ok($$select api.set_member_permission_decision('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000006','view_all','allow','tenant',null,null,null,null,true,false,null,null,'Attempt unauthorized permission')$$,'42501',null,'delegated management category cannot grant unused permission');
reset role;
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason)
values('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000004','view_all','allow','tenant',true,'90000000-0000-0000-0000-000000000002','Admin use authority within envelope');
set local role authenticated;
select api.set_member_permission_decision('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000006','view_all','allow','tenant',null,null,null,null,true,false,null,null,'Authorized delegated grant');
reset role;
select extensions.ok(exists(select 1 from iam.member_permission_decisions where membership_id='92000000-0000-0000-0000-000000000006' and source_delegation_id is not null),'delegated decision records exact source');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000006',true);
set local role authenticated;
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','view_all','read'),'live delegated decision allows beneficiary');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
select api.revoke_delegation('91000000-0000-0000-0000-000000000001',
 (select id from iam.delegation_envelopes where delegate_membership_id='92000000-0000-0000-0000-000000000004'),'Revoke contract delegation');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000006',true);
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','view_all','read'),'revoking envelope stops its decisions');
reset role;
select extensions.is((select status from iam.member_permission_decisions where membership_id='92000000-0000-0000-0000-000000000006'),'suspended','delegated decision is suspended for review');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.adopt_permission_decision('91000000-0000-0000-0000-000000000001',
 (select id from iam.member_permission_decisions where membership_id='92000000-0000-0000-0000-000000000006'),'Superadmin adopts reviewed decision');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000006',true);
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','view_all','read'),'explicit adoption restores independently reviewed grant');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
select extensions.throws_ok($$select api.set_permission_action('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000005','operations.contract.read','read','deny','tenant',null,null,null,null,now(),null,'Must use read write decision API')$$,'42501',null,'named action API rejects read/write instead of ignoring it');
select api.set_permission_action('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000005','operations.contract.read','approve','allow','tenant',null,null,null,null,now(),null,'Explicit approval not export');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000005',true);
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','approve'),'explicit approve grant authorizes approval');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','export'),'approval still does not imply export');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
select api.set_permission_action('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000005','operations.contract.read','approve','deny','tenant',null,null,null,null,now(),null,'Explicit approval deny');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000005',true);
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','approve'),'named action deny overrides approval');
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','read'),'named action deny does not deny unrelated read');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
reset role;
insert into iam.roles(id,tenant_id,role_key,label,role_family,created_by) values('94000000-0000-0000-0000-000000000001','91000000-0000-0000-0000-000000000001','contract_actions','Contract actions','employee','90000000-0000-0000-0000-000000000002');
set local role authenticated;
select extensions.throws_ok($$select api.publish_role_version('91000000-0000-0000-0000-000000000001','94000000-0000-0000-0000-000000000001','[{"permission_key":"operations.contract.read","scope_kind":"tenant","can_read":true,"can_write":true,"actions":["read"]}]'::jsonb,'Reject inconsistent write')$$,'23514',null,'role publisher rejects hidden write behind read action');
select extensions.throws_ok($$select api.publish_role_version('91000000-0000-0000-0000-000000000001','94000000-0000-0000-0000-000000000001','[{"permission_key":"operations.contract.read","scope_kind":"tenant","can_read":false,"can_write":false,"actions":["write"]}]'::jsonb,'Reject action without flags')$$,'23514',null,'role publisher rejects write action without matching flags');
select extensions.lives_ok($$select api.publish_role_version('91000000-0000-0000-0000-000000000001','94000000-0000-0000-0000-000000000001','[{"permission_key":"operations.contract.read","scope_kind":"tenant","can_read":false,"can_write":false,"actions":["approve"]}]'::jsonb,'Explicit approve role')$$,'Superadmin publishes exact approval role');
select api.create_delegation('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000004','tenant',null,null,array['role_assignment'],now(),now()+interval '1 hour','Bounded role assignment authority');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000004',true);
select extensions.throws_ok($$select api.assign_membership_role('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000007','94000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='94000000-0000-0000-0000-000000000001' and version_no=1),'{}'::uuid[],'{}'::uuid[],now(),null,'Attempt approval role escalation')$$,'42501',null,'Admin cannot assign an action they cannot use or delegate');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
select api.set_permission_action('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000004','operations.contract.read','approve','allow','tenant',null,null,null,null,now(),null,'Admin approval authority');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000004',true);
select extensions.lives_ok($$select api.assign_membership_role('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000007','94000000-0000-0000-0000-000000000001',(select id from iam.role_versions where role_id='94000000-0000-0000-0000-000000000001' and version_no=1),'{}'::uuid[],'{}'::uuid[],now(),null,'Valid approval role assignment')$$,'authorized delegated assignment succeeds');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000007',true);
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','approve'),'beneficiary receives delegated role action');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
select api.revoke_delegation('91000000-0000-0000-0000-000000000001',(select id from iam.delegation_envelopes where delegate_membership_id='92000000-0000-0000-0000-000000000004' and status='active'),'Close assignment authority');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000007',true);
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','approve'),'revoked source removes delegated role action');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000002',true);
select extensions.lives_ok($$select * from api.set_default_permission_profile('91000000-0000-0000-0000-000000000001','employee','Operations profile','[{"permission_key":"operations.contract.read","scope_kind":"tenant","can_read":false,"can_write":false,"actions":["export"]}]'::jsonb,'selected_existing_users',array['92000000-0000-0000-0000-000000000007'::uuid],'Selected export profile')$$,'profile supports exact named action from independent module');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000007',true);
select extensions.ok(api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','export'),'named profile action is effective');
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','operations.contract.read','approve'),'export profile does not imply approve');
select extensions.throws_ok($$insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by) values('91000000-0000-0000-0000-000000000001',gen_random_uuid(),1,'employee','draft',auth.uid())$$,'42501',null,'browser cannot write role versions directly');
select set_config('request.jwt.claim.sub','90000000-0000-0000-0000-000000000008',true);
select extensions.ok(not api.authorize('91000000-0000-0000-0000-000000000001','view_all','read'),'Subowner has no automatic company access');
select extensions.lives_ok($$select api.platform_set_membership_status('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000006','suspended','Platform enforcement action')$$,'platform may suspend exact company account');
select extensions.lives_ok($$select api.platform_set_membership_status('91000000-0000-0000-0000-000000000001','92000000-0000-0000-0000-000000000006','active','Platform reactivation action')$$,'platform may reactivate exact company account');
reset role;
select * from extensions.finish();
rollback;
