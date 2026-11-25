begin;
select extensions.plan(13);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
select ('00000000-0000-0000-0000-0000000008'||lpad(n::text,2,'0'))::uuid,'authenticated','authenticated',e,'',now(),'{}','{}',now(),now()
from (values (1,'r3-owner@example.test'),(2,'r3-sub@example.test'),(3,'r3-sa@example.test'),(11,'r3-lim@example.test'),(12,'r3-ent@example.test'),(13,'r3-plat@example.test'),(14,'r3-rep@example.test'),(15,'r3-adm@example.test')) v(n,e);
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000801');
insert into iam.platform_operators(user_id,operator_role,created_by) values('00000000-0000-0000-0000-000000000802','subowner','00000000-0000-0000-0000-000000000801');
insert into core.tenants(id,name,created_by) values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','R3 Co','00000000-0000-0000-0000-000000000801');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-0000000e0803','eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','00000000-0000-0000-0000-000000000803','company_superadmin','active','r3-sa@example.test');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','hse',now()-interval '1 day','infinity','00000000-0000-0000-0000-000000000801','R3 test','complimentary');
create temporary table inv(name text,invitation_id uuid,token text) on commit drop;
grant insert,select on table pg_temp.inv to authenticated;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000803',true);
set local role authenticated;
insert into inv select 'lim',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-lim@example.test','employee',interval '7 days','L','[{"permission_key":"hse.findings.read","decision":"deny"},{"permission_key":"hse.forms.read","decision":"allow"}]'::jsonb,'Starter access');
insert into inv select 'ent',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-ent@example.test','employee',interval '7 days','E','[{"permission_key":"hse.forms.read","decision":"allow"},{"permission_key":"hse.findings.read","decision":"deny"}]'::jsonb,'Starter access');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000802',true);
insert into inv select 'plat',* from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-plat@example.test','P','employee',interval '7 days','[{"permission_key":"hse.forms.read","decision":"allow"},{"permission_key":"hse.findings.read","decision":"deny"}]'::jsonb,'Starter access');
reset role;
-- 1 limits added after creation (both keys)
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason) values
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','10000000-0000-0000-0000-0000000e0803','hse.findings.read',true,false,'00000000-0000-0000-0000-000000000801','limit test'),
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','10000000-0000-0000-0000-0000000e0803','hse.forms.read',true,false,'00000000-0000-0000-0000-000000000801','limit test');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000811',true);
set local role authenticated;
select api.accept_my_invitation((select token from inv where name='lim'));
reset role;
select extensions.is((select count(*)::int from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where m.user_id='00000000-0000-0000-0000-000000000811'),0,'R1 accept-time limit skips both Allow and Deny');
select extensions.is((select count(*)::int from audit.events e where e.action_key='iam.invitation.initial_access.applied' and e.summary->>'skipped' like '%inviter_limited%' and e.summary->'skipped' @> '[{"why":"inviter_limited"}]'),1,'R2 the skip is audited as inviter_limited');
delete from iam.superadmin_capability_limits where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01';
-- 2 inviter personally restricted from the module after creation
insert into core.entitlement_grants(tenant_id,membership_id,module_key,can_use,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','10000000-0000-0000-0000-0000000e0803','hse',false,now()-interval '1 hour','infinity','00000000-0000-0000-0000-000000000801','restrict inviter','complimentary');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000812',true);
set local role authenticated;
select api.accept_my_invitation((select token from inv where name='ent'));
reset role;
select extensions.is((select string_agg(permission_key||':'||decision,',') from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where m.user_id='00000000-0000-0000-0000-000000000812' and d.status='active'),'hse.findings.read:deny','R3 inviter lost the module: Allow skipped, Deny applied');
select extensions.ok(exists(select 1 from audit.events e where e.action_key='iam.invitation.initial_access.applied' and e.summary->'skipped' @> '[{"why":"inviter_not_entitled"}]'),'R4 audited as inviter_not_entitled');
-- 3 platform origin after member.permissions withdrawn
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000801',true);
set local role authenticated;
select api.set_subowner_platform_permission('00000000-0000-0000-0000-000000000802','member.permissions',false,'Withdraw for test');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000813',true);
set local role authenticated;
select api.accept_my_invitation((select token from inv where name='plat'));
reset role;
select extensions.is((select string_agg(permission_key||':'||decision,',') from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where m.user_id='00000000-0000-0000-0000-000000000813' and d.status='active'),'hse.findings.read:deny','R5 platform inviter lost member.permissions: Allow skipped, Deny applied');
-- catalog listing
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000803',true);
set local role authenticated;
select extensions.ok((select count(*) from api.list_permission_catalog())>0,'R6 a company Superadmin can list the enabled catalog');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000802',true);
select extensions.ok((select count(*) from api.list_permission_catalog())>0,'R7 an operator can list it');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000811',true);
select extensions.throws_ok($$select * from api.list_permission_catalog()$$,'42501',null,'R8 an ordinary member cannot');
reset role;
delete from core.entitlement_grants where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01' and membership_id is not null;
-- Superadmin invites an Admin (not Superadmin level)
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000803',true);
set local role authenticated;
select extensions.lives_ok($$insert into inv select 'adm',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-adm@example.test','company_admin',interval '7 days','Adam','[{"permission_key":"hse.forms.read","decision":"allow"},{"permission_key":"hse.findings.read","decision":"deny"}]'::jsonb,'Admin starter access')$$,'R9 a Superadmin invites an Admin with initial access');
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-sa2@example.test','company_superadmin')$$,'42501',null,'R10 but not a Superadmin');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000815',true);
select api.accept_my_invitation((select token from inv where name='adm'));
reset role;
select extensions.is((select m.member_role||':'||string_agg(d.permission_key||'='||d.decision,',' order by d.permission_key) from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where m.user_id='00000000-0000-0000-0000-000000000815' and d.status='active' group by m.member_role),'company_admin:hse.findings.read=deny,hse.forms.read=allow','R11 the Admin joins as company_admin with the agreed access');
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason) values
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','10000000-0000-0000-0000-0000000e0803','hse.reports.read',true,false,'00000000-0000-0000-0000-000000000801','limit test');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000803',true);
set local role authenticated;
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-adm2@example.test','company_admin',interval '7 days','A2','[{"permission_key":"hse.reports.read","decision":"allow"}]'::jsonb,'Admin starter access')$$,'42501',null,'R12 the same per-permission limits apply to Admin invitations');
reset role;
-- An Admin invitation dies when its Superadmin is suspended before acceptance
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000803',true);
set local role authenticated;
insert into inv select 'adm3',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0d01','r3-adm3@example.test','company_admin',interval '7 days','Adam3');
reset role;
set local session_replication_role=replica;
update iam.memberships set status='suspended' where id='10000000-0000-0000-0000-0000000e0803';
set local session_replication_role=origin;
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values ('00000000-0000-0000-0000-000000000816','authenticated','authenticated','r3-adm3@example.test','',now(),'{}','{}',now(),now());
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000816',true);
set local role authenticated;
select extensions.throws_ok($$select api.accept_my_invitation((select token from inv where name='adm3'))$$,'22023',null,'R13 a suspended Superadmin cannot mint an Admin through a pending invitation');
reset role;
-- Replace/skip of pre-existing decisions: not reachable through acceptance. Reactivating a membership
-- runs private.reset_contract_authorizations, which suspends all its active decisions first (and the
-- own-restriction guard refuses to clear a protected one), so no conflicting active decision exists at accept time.
select * from extensions.finish();
rollback;
