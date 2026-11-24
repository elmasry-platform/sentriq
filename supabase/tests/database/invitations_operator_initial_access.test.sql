begin;
select extensions.plan(24);
create temporary table inv(name text,invitation_id uuid,token text) on commit drop;
grant insert,select on table pg_temp.inv to authenticated;

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000501','authenticated','authenticated','inv-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000502','authenticated','authenticated','inv-superadmin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000503','authenticated','authenticated','inv-subowner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000511','authenticated','authenticated','new-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000512','authenticated','authenticated','new-b@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000513','authenticated','authenticated','new-c@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000514','authenticated','authenticated','new-d@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000515','authenticated','authenticated','stranger@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000516','authenticated','authenticated','empty-sa@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000501');
insert into iam.platform_operators(user_id,operator_role,created_by)
 values('00000000-0000-0000-0000-000000000503','subowner','00000000-0000-0000-0000-000000000501');
insert into core.tenants(id,name,created_by) values
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','Inv A','00000000-0000-0000-0000-000000000501'),
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeee0b01','Inv B no modules','00000000-0000-0000-0000-000000000501');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-0000000e0502','eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','00000000-0000-0000-0000-000000000502','company_superadmin','active','inv-superadmin@example.test'),
 ('10000000-0000-0000-0000-0000000e0516','eeeeeeee-eeee-eeee-eeee-eeeeeeee0b01','00000000-0000-0000-0000-000000000516','company_superadmin','active','empty-sa@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by) values
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','hse','active','00000000-0000-0000-0000-000000000501');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
select tenant_id,module_key,created_at,'infinity'::timestamptz,changed_by,'Invitation test','complimentary','legacy_backfill',id
from core.tenant_entitlements where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01';

select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000502',true);
set local role authenticated;

-- Company Superadmin
select extensions.lives_ok($$insert into inv select 'a',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','New-A@Example.test','employee',interval '7 days','Alice Example','[{"permission_key":"hse.forms.read","decision":"deny"},{"permission_key":"hse.forms.manage","decision":"allow"}]'::jsonb,'Starter access for a new inspector')$$,'S1 Superadmin invites an Employee with a name and initial access');
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','adm@example.test','company_admin')$$,'42501',null,'S2 Superadmin cannot invite an Admin');
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','x1@example.test','employee',interval '7 days','X','[{"permission_key":"hse.forms.read","decision":"deny"}]'::jsonb)$$,'22023',null,'S3 initial access needs a reason');
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','x2@example.test','employee',interval '7 days','X','[{"permission_key":"nope.key","decision":"deny"}]'::jsonb,'reason ok')$$,'22023',null,'S4 unknown permission key is rejected');
select extensions.throws_ok($$select * from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','x3@example.test','X','employee',interval '7 days','[]'::jsonb,'reason ok')$$,'42501',null,'S5 a Superadmin cannot use the platform invitation RPC');
select extensions.throws_ok($$select * from api.list_invitations()$$,'42501',null,'S6 a Superadmin must name their own company to list');
select extensions.is((api.list_invitations('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01')->'rows'->0) ? 'token_hash',false,'S7 the list never exposes token data');
select extensions.is(jsonb_array_length(api.list_invitations('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01')->'rows'),1,'S8 Superadmin sees the pending invitation');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000516',true);
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0b01','y@example.test','employee')$$,'42501',null,'S9 a Superadmin whose company has no live module cannot invite');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000502',true);
select extensions.throws_ok($$select * from api.list_invitations('eeeeeeee-eeee-eeee-eeee-eeeeeeee0b01')$$,'42501',null,'S10 a Superadmin cannot list another company');

-- Operators
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000501',true);
select extensions.lives_ok($$insert into inv select 'b',* from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','new-b@example.test','Bob Example','employee',interval '7 days','[{"permission_key":"hse.forms.read","decision":"allow"},{"permission_key":"hse.audit.read","decision":"deny"}]'::jsonb,'Operator-set access')$$,'O1 Owner invites an Employee with initial access');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000503',true);
select extensions.lives_ok($$insert into inv select 'c',* from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','new-c@example.test','Carol Example','company_admin',interval '7 days','[]'::jsonb,'Admin for company A')$$,'O2 Sub-owner invites an Admin');
select extensions.throws_ok($$select * from api.platform_create_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','new-d@example.test','Dan','company_superadmin',interval '7 days','[{"permission_key":"hse.forms.read","decision":"deny"}]'::jsonb,'reason ok')$$,'22023',null,'O3 initial decisions are not supported on a Superadmin invitation');
select extensions.is(jsonb_array_length(api.list_invitations()->'rows'),3,'O4 operators list invitations across companies');
select extensions.lives_ok($$select api.revoke_invitation((select invitation_id from inv where name='c'),'Changed our mind')$$,'O5 an operator can revoke an invitation with a reason');

-- Accept
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000515',true);
select extensions.throws_ok($$select api.accept_my_invitation((select token from inv where name='a'))$$,'22023',null,'A1 someone with a different verified email cannot accept');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000513',true);
select extensions.throws_ok($$select api.accept_my_invitation((select token from inv where name='c'))$$,'22023',null,'A2 a revoked invitation cannot be accepted');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000511',true);
select extensions.lives_ok($$select api.accept_my_invitation((select token from inv where name='a'))$$,'A3 the invited person accepts with their own session');
select extensions.throws_ok($$select api.accept_my_invitation((select token from inv where name='a'))$$,'22023',null,'A4 an accepted invitation cannot be reused');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000512',true);
select extensions.lives_ok($$select api.accept_my_invitation((select token from inv where name='b'))$$,'A5 the operator-invited person accepts');
reset role;
select extensions.is((select display_name from iam.memberships where user_id='00000000-0000-0000-0000-000000000511' and tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01'),'Alice Example','A6 the invited name becomes the member name');
select extensions.is((select string_agg(permission_key||':'||decision||':'||protected_origin::text,',' order by permission_key) from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where m.user_id='00000000-0000-0000-0000-000000000511' and d.status='active'),'hse.forms.manage:allow:false,hse.forms.read:deny:false','A7 company initial access is applied as ordinary decisions granted by the Superadmin');
select extensions.is((select string_agg(permission_key||':'||decision||':'||protected_origin::text,',' order by permission_key) from iam.member_permission_decisions d join iam.memberships m on m.id=d.membership_id where m.user_id='00000000-0000-0000-0000-000000000512' and d.status='active'),'hse.audit.read:deny:true,hse.forms.read:allow:true','A8 operator initial access is applied as protected operator decisions');
select extensions.is((select count(*)::int from audit.events where action_key='iam.invitation.initial_access.applied'),2,'A9 applying initial access is audited');
select * from extensions.finish();
rollback;
