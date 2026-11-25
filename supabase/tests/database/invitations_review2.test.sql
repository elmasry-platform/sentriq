begin;
select extensions.plan(7);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000701','authenticated','authenticated','r2-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000702','authenticated','authenticated','r2-sub@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000703','authenticated','authenticated','r2-sa@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000701');
insert into iam.platform_operators(user_id,operator_role,created_by) values('00000000-0000-0000-0000-000000000702','subowner','00000000-0000-0000-0000-000000000701');
insert into core.tenants(id,name,created_by) values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','R2 Co','00000000-0000-0000-0000-000000000701');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-0000000e0703','eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','00000000-0000-0000-0000-000000000703','company_superadmin','active','r2-sa@example.test');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','hse',now()-interval '1 day','infinity','00000000-0000-0000-0000-000000000701','R2 test','complimentary');
create temporary table inv(name text,invitation_id uuid,token text) on commit drop;
grant insert,select on table pg_temp.inv to authenticated;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000701',true);
set local role authenticated;
insert into inv select 'a',* from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','r2-a@example.test','A','employee',interval '7 days','[]'::jsonb,'Invitation created');
select api.set_subowner_platform_permission('00000000-0000-0000-0000-000000000702','superadmin.invite',false,'Withdraw for test');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000702',true);
select extensions.throws_ok($$select api.list_invitations()$$,'42501',null,'W1 Sub-owner without superadmin.invite cannot list all');
select extensions.throws_ok($$select api.list_invitations('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01')$$,'42501',null,'W2 nor one company');
select extensions.throws_ok($$select api.revoke_invitation((select invitation_id from inv where name='a'),'Trying anyway')$$,'22023',null,'W3 nor revoke');
select extensions.throws_ok($$select * from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','r2-n@example.test','N',null,interval '7 days','[]'::jsonb,'Invitation created')$$,'42501',null,'W4 NULL level refused with 42501 (platform)');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000703',true);
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','r2-n2@example.test',null)$$,'42501',null,'W5 NULL level refused with 42501 (company)');
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','r2-s@example.test','employee',interval '7 days','S','[]'::jsonb,'ab')$$,'22023',null,'W6 a 2-char reason is validated, not a table CHECK');
reset role;
update iam.invitations set created_at=now()-interval '2 days',expires_at=now()-interval '1 day' where email='r2-a@example.test';
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000703',true);
select api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0c01','r2-a@example.test','employee');
reset role;
select extensions.is((select count(*)::int from audit.events where action_key='iam.invitation.revoked' and summary->>'automatic'='true'),1,'W7 reinviting after expiry writes an automatic-revoke audit row');
select * from extensions.finish();
rollback;
