begin;
select extensions.plan(37);
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
 ('00000000-0000-0000-0000-000000000516','authenticated','authenticated','empty-sa@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000517','authenticated','authenticated','exp@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000518','authenticated','authenticated','svc@example.test','',now(),'{}','{}',now(),now());
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
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','adm@example.test','company_superadmin')$$,'42501',null,'S2 Superadmin cannot invite Superadmin level');
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

-- Review hardening
reset role;
insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
 values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','10000000-0000-0000-0000-0000000e0502','hse.findings.read',true,false,'00000000-0000-0000-0000-000000000501','limit test');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000502',true);
set local role authenticated;
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','lim@example.test','employee',interval '7 days','L','[{"permission_key":"hse.findings.read","decision":"deny"}]'::jsonb,'reason ok')$$,'42501',null,'H1 a per-permission Superadmin limit blocks initial access (Deny too)');
reset role;
delete from iam.superadmin_capability_limits where capability_key='hse.findings.read';
set local role authenticated;
select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','nm@example.test','employee',interval '7 days','N','[{"permission_key":"core.structure.manage","decision":"allow"}]'::jsonb,'reason ok')$$,'42501',null,'H2 Allow on a module the company does not have is refused at creation');
reset role;
create temporary table dec_before as select count(*)::int c from iam.member_permission_decisions;
set local role authenticated;
select extensions.lives_ok($$insert into inv select 'd',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','new-d@example.test','employee',interval '7 days','Dina Example','[{"permission_key":"hse.forms.read","decision":"deny"},{"permission_key":"hse.forms.manage","decision":"allow"}]'::jsonb,'Starter access')$$,'H3 create an invitation, then lose the inviter before it is accepted');
reset role;
select extensions.is((select count(*)::int from iam.member_permission_decisions),(select c from dec_before),'H4 nothing is written before acceptance');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000501',true);
set local role authenticated;
select api.platform_set_membership_status('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','10000000-0000-0000-0000-0000000e0502','suspended','inviter leaves');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000514',true);
set local role authenticated;
select extensions.throws_ok($$select api.accept_my_invitation((select token from inv where name='d'))$$,'22023',null,'H5 a suspended inviter makes the pending invitation unusable');
reset role;
select extensions.is((select count(*)::int from iam.memberships where user_id='00000000-0000-0000-0000-000000000514'),0,'H6 no membership and no decisions are created');
select extensions.is((select count(*)::int from audit.events where action_key='iam.invitation.initial_access.applied' and summary->>'invitation_id'=(select invitation_id::text from inv where name='d')),0,'H7 nothing was applied or audited as applied');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000501',true);
set local role authenticated;
select api.platform_set_membership_status('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','10000000-0000-0000-0000-0000000e0502','active','inviter back');
reset role;
-- expired invitation
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000502',true);
set local role authenticated;
select extensions.lives_ok($$insert into inv select 'e',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','exp@example.test','employee')$$,'H8 create an invitation to expire');
reset role;
update iam.invitations set created_at=now()-interval '2 days',expires_at=now()-interval '1 day' where email='exp@example.test';
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000517',true);
set local role authenticated;
select extensions.throws_ok($$select api.accept_my_invitation((select token from inv where name='e'))$$,'22023',null,'H9 an expired invitation cannot be accepted');
-- service-role regression
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000502',true);
insert into inv select 'f',* from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','svc@example.test','employee');
select set_config('t.tok',(select token from inv where name='f'),true);
reset role;
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select extensions.lives_ok($$select api.accept_invitation(current_setting('t.tok'),'00000000-0000-0000-0000-000000000518')$$,'H10 the service-role accept path still works');
reset role;
select extensions.throws_ok($$select private.normalize_invitation_decisions('{"a":1}'::jsonb)$$,'22023',null,'H11 non-array decisions are rejected');
select extensions.throws_ok($$select private.normalize_invitation_decisions('[{"permission_key":"hse.forms.read","decision":"deny"},{"permission_key":"hse.forms.read","decision":"allow"}]'::jsonb)$$,'22023',null,'H12 duplicate keys are rejected');
select extensions.throws_ok($$select private.normalize_invitation_decisions((select jsonb_agg(jsonb_build_object('permission_key','hse.forms.read','decision','deny')) from generate_series(1,101)))$$,'22023',null,'H13 more than 100 entries are rejected');
select * from extensions.finish();
rollback;
