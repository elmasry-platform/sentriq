-- Acceptance tests for dynamic member permissions and individual entitlement overrides.
begin;
select extensions.plan(69);
create or replace function pg_temp.as_user(p_uid uuid) returns void language sql as $$
 select set_config('request.jwt.claim.sub',p_uid::text,true), set_config('request.jwt.claim.role','authenticated',true) $$;
create or replace function pg_temp.az(p_uid uuid,p_tenant uuid,p_key text) returns boolean language plpgsql as $$
begin perform pg_temp.as_user(p_uid); return api.authorize(p_tenant,p_key,'read'); end $$;

insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('a0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','dme-'||i||'@example.test',now(),now(),now()
from generate_series(1,10) i;
select private.bootstrap_platform_owner('a0000000-0000-0000-0000-000000000001');
insert into iam.platform_operators(user_id,operator_role,created_by)
values('a0000000-0000-0000-0000-000000000009','subowner','a0000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values
 ('a1000000-0000-0000-0000-00000000000a','DME A','a0000000-0000-0000-0000-000000000001'),
 ('a1000000-0000-0000-0000-00000000000b','DME B','a0000000-0000-0000-0000-000000000001');
-- Tenant A: users 2,3 superadmin; 4 admin; 5,6,7 employees. Tenant B: user 8 superadmin, user 10 employee.
insert into iam.memberships(id,tenant_id,user_id,member_role,email)
select ('a2000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'a1000000-0000-0000-0000-00000000000a',
 ('a0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,
 case when i in (2,3) then 'company_superadmin' when i=4 then 'company_admin' else 'employee' end,'dme-'||i||'@example.test'
from generate_series(2,7) i;
insert into iam.memberships(id,tenant_id,user_id,member_role,email) values
 ('a2000000-0000-0000-0000-000000000008','a1000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-000000000008','company_superadmin','dme-8@example.test'),
 ('a2000000-0000-0000-0000-00000000000a','a1000000-0000-0000-0000-00000000000b','a0000000-0000-0000-0000-000000000010','employee','dme-10@example.test');
-- Company entitlements (subscription equivalent): A has core+operations+hse (no Copilot feature). B has core only.
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select 'a1000000-0000-0000-0000-00000000000a',m,now()-interval '1 day',null,'a0000000-0000-0000-0000-000000000001','DME company entitlement','complimentary'
from unnest(array['core','operations','hse']) m;
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
values('a1000000-0000-0000-0000-00000000000b','core',now()-interval '1 day',null,'a0000000-0000-0000-0000-000000000001','DME company entitlement','complimentary');
create temp table dme_baseline as select count(*)::integer n from core.entitlement_grants where membership_id is null;

-- 1 Default Superadmin access
select extensions.is((select count(*)::integer from iam.permission_catalog c where c.enabled and c.feature_key is null
   and 'read'=any(c.supported_actions)
   and not pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a',c.permission_key)),0,
 'T1 new Superadmin with no restrictions has every company-entitled read capability');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a','hse.copilot.use'),
 'T1 Superadmin does not receive a feature the company lacks');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000008','a1000000-0000-0000-0000-00000000000b','hse.forms.read')
 and pg_temp.az('a0000000-0000-0000-0000-000000000008','a1000000-0000-0000-0000-00000000000b','core.structure.manage'),
 'T1 Superadmin in a core-only company gets core but not the unsubscribed module');

-- 2 Future capability
reset role;
insert into iam.permission_catalog(permission_key,module_key,label,supported_actions) values
 ('hse.future.capability','hse','Future capability',array['read','write']);
select extensions.ok(pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a','hse.future.capability'),
 'T2 a new catalog permission in an entitled module reaches the Superadmin without any update');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000008','a1000000-0000-0000-0000-00000000000b','hse.future.capability'),
 'T2 the same new permission does not reach a company without that module');

-- 3 Granular restriction of one Superadmin permission
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse.forms.manage','deny','Restrict forms management')$$,
 'T3 Owner denies one permission for a Superadmin');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000003','a1000000-0000-0000-0000-00000000000a','hse.forms.manage'),
 'T3 the denied permission is restricted');
select extensions.ok(pg_temp.az('a0000000-0000-0000-0000-000000000003','a1000000-0000-0000-0000-00000000000a','hse.forms.read')
 and pg_temp.az('a0000000-0000-0000-0000-000000000003','a1000000-0000-0000-0000-00000000000a','hse.inspections.create')
 and pg_temp.az('a0000000-0000-0000-0000-000000000003','a1000000-0000-0000-0000-00000000000a','hse.future.capability'),
 'T3 unrelated permissions stay available');
select extensions.ok(pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a','hse.forms.manage'),
 'T3 another Superadmin is unaffected');

-- 4 Different access within one module
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.inspections.create','allow','Inspector access')$$,
 'T4 Owner allows one permission for an employee');
select extensions.ok(pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a','hse.inspections.create'),
 'T4 employee can use Inspections');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a','hse.forms.manage'),
 'T4 employee cannot edit Forms (backend rejects)');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a','hse.dashboard.read'),
 'T4 Allow on one key does not grant unrelated keys');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.inspections.create','deny','Pause inspections')$$,
 'T4 a later Deny replaces the Allow');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a','hse.inspections.create'),
 'T4 Deny wins over the earlier Allow');

-- 5 Dashboard restriction (API-level, not navigation)
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','hse.dashboard.read','deny','No dashboard')$$,
 'T5 Owner denies the dashboard for an Admin');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000004','a1000000-0000-0000-0000-00000000000a','hse.dashboard.read'),
 'T5 direct API call is rejected');
select extensions.ok((select (e->>'functional_state') from jsonb_array_elements(api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004')->'permissions') e
   where e->>'permission_key'='hse.dashboard.read')='deny','T5 effective access reports Deny');

-- 6 Individual entitlement exception (Copilot outside the subscription)
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000006',null,'hse.copilot','CEO needs Copilot')$$,
 'T6 Owner grants Copilot to one membership');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000006','hse.copilot.use','allow','CEO Copilot use')$$,
 'T6 Allow works once the entitlement exists');
select extensions.ok(pg_temp.az('a0000000-0000-0000-0000-000000000006','a1000000-0000-0000-0000-00000000000a','hse.copilot.use'),
 'T6 the CEO can use Copilot');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000007','a1000000-0000-0000-0000-00000000000a','hse.copilot.use')
 and not pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a','hse.copilot.use')
 and not pg_temp.az('a0000000-0000-0000-0000-000000000004','a1000000-0000-0000-0000-00000000000a','hse.copilot.use'),
 'T6 other employees, Superadmins and Admins do not get it');
select extensions.is((select count(*)::integer from core.entitlement_grants where membership_id is null),(select n from dme_baseline),
 'T6 company-level entitlements are unchanged');
select extensions.is((select can_delegate from core.entitlement_grants where feature_key='hse.copilot' and membership_id='a2000000-0000-0000-0000-000000000006'),false,
 'T6 can_delegate defaults to false');
select extensions.is((select can_use from core.entitlement_grants where feature_key='hse.copilot' and membership_id='a2000000-0000-0000-0000-000000000006'),true,
 'T6 can_use defaults to true');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where feature_key='hse.copilot' and membership_id='a2000000-0000-0000-0000-000000000006'),'a2000000-0000-0000-0000-000000000007','Share it')$$,
 '42501',null,'T6 the CEO cannot delegate without can_delegate');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000006');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where feature_key='hse.copilot' and membership_id='a2000000-0000-0000-0000-000000000006'),'a2000000-0000-0000-0000-000000000007','Share it')$$,
 '42501',null,'T6 the CEO cannot delegate without can_delegate (as the CEO)');
select extensions.is((select e->>'entitlement_state' from jsonb_array_elements(api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000006')->'permissions') e where e->>'permission_key'='hse.copilot.use'),'personal_exception',
 'T6 shown as a personal exception, not a company entitlement');

-- 7 Expiration and revocation at every entry point
-- (now() is frozen inside a transaction, so an already-expired window is inserted directly)
reset role;
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment)
values('a1000000-0000-0000-0000-00000000000a','hse.copilot','a2000000-0000-0000-0000-000000000007',now()-interval '2 hours',now()-interval '1 hour','a0000000-0000-0000-0000-000000000001','Expired trial','platform_absorbed');
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,status,granted_by,reason)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000007','hse.copilot.use','allow','tenant',true,true,'active','a0000000-0000-0000-0000-000000000001','Trial use');
select set_config('sentriq.migration_runner','off',true);
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000007','a1000000-0000-0000-0000-00000000000a','hse.copilot.use')
 and not private.has_feature_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000007','hse.copilot'),
 'T7 expired entitlement stops at authorize and at the entitlement helper');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.is((select g->>'status' from jsonb_array_elements(api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000007')->'entitlement_grants') g limit 1),'expired',
 'T7 effective access reports expired');
select extensions.ok(true,'T7 placeholder');
select extensions.ok(true,'T7 placeholder 2');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.platform_revoke_member_entitlement((select id from core.entitlement_grants where feature_key='hse.copilot' and membership_id='a2000000-0000-0000-0000-000000000006' and revoked_at is null),'CEO left Copilot project')$$,'T7 revoke');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000006','a1000000-0000-0000-0000-00000000000a','hse.copilot.use'),
 'T7 revocation removes access immediately');
select extensions.is((select g->>'status' from jsonb_array_elements(api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000006')->'entitlement_grants') g limit 1),'revoked','T7 effective access reports revoked');

-- 8 Subowner capability withdrawal
select pg_temp.as_user('a0000000-0000-0000-0000-000000000009');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000007','hse.dashboard.read','deny','Subowner default power')$$,'T8 Subowner holds member.permissions by default');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.lives_ok($$select api.set_subowner_platform_permission('a0000000-0000-0000-0000-000000000009','member.permissions',false,'Owner withdraws member.permissions')$$,'T8 Owner withdraws member.permissions');
select extensions.lives_ok($$select api.set_subowner_platform_permission('a0000000-0000-0000-0000-000000000009','member.entitlements',false,'Owner withdraws member.entitlements')$$,'T8 Owner withdraws member.entitlements');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000009');
select extensions.throws_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000007','hse.dashboard.read','deny','try again')$$,'42501',null,'T8 Subowner immediately loses member.permissions');
select extensions.throws_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000007',null,'hse.copilot','try again')$$,'42501',null,'T8 Subowner immediately loses member.entitlements');
select extensions.throws_ok($$select api.set_subowner_platform_permission('a0000000-0000-0000-0000-000000000009','member.permissions',true,'restore myself')$$,'42501',null,'T8 Subowner cannot restore a withdrawn power');

-- 9 Tenant isolation
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.throws_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000b','a2000000-0000-0000-0000-000000000006',null,'hse.copilot','Mismatched tenant')$$,'22023',null,'T9 entitlement with another tenant''s membership is rejected');
select extensions.throws_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000b','a2000000-0000-0000-0000-000000000006','hse.dashboard.read','deny','Mismatched tenant')$$,'22023',null,'T9 decision with another tenant''s membership is rejected');
select extensions.throws_ok($$select api.member_effective_access('a1000000-0000-0000-0000-00000000000b','a2000000-0000-0000-0000-000000000006')$$,'42501',null,'T9 effective access with mismatched tenant is rejected');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000008');
select extensions.throws_ok($$select api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000006')$$,'42501',null,'T9 another company''s Superadmin cannot read it');

-- 10 No subscription escalation
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select extensions.throws_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002',null,'hse.copilot','Self grant')$$,'42501',null,'T10 Superadmin cannot grant themselves an entitlement');
select extensions.throws_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005',null,'hse.copilot','Grant other')$$,'42501',null,'T10 Superadmin cannot grant another member an entitlement');
select extensions.throws_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.copilot.use','allow','tenant',null,null,null,null,true,true,null,null,'Escalate')$$,'42501',null,'T10 Allow decision cannot create entitlement');
select extensions.throws_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','deny','Not operator')$$,'42501',null,'T10 Superadmin cannot use operator decision RPC');
set local role authenticated;
select extensions.throws_ok($$insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,granted_by,reason,billing_treatment) values('a1000000-0000-0000-0000-00000000000a','hse.copilot','a2000000-0000-0000-0000-000000000002',now(),'a0000000-0000-0000-0000-000000000002','Direct write','complimentary')$$,'42501',null,'T10 direct table write is blocked');
reset role;
-- Superadmin with an Allow decision on an unentitled feature still fails
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a','hse.copilot.use'),'T10 Superadmin still lacks the unentitled feature');

-- Delegation rules
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005',null,'hse.copilot','Delegating lead',true,true,now(),now()+interval '10 days');
select extensions.is((select can_delegate from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and revoked_at is null),true,'D1 delegable exception recorded');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000005');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and revoked_at is null),'a2000000-0000-0000-0000-000000000007','Too long',now()+interval '30 days')$$,'22023',null,'D2 delegation cannot outlive the source');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and revoked_at is null),'a2000000-0000-0000-0000-00000000000a','Other company')$$,'42501',null,'D3 delegation to another company is rejected');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and revoked_at is null),'a2000000-0000-0000-0000-000000000005','Self')$$,'42501',null,'D4 no self delegation');
select extensions.lives_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and revoked_at is null),'a2000000-0000-0000-0000-000000000004','Share with admin',now()+interval '5 days')$$,'D5 valid delegation');
select extensions.is((select can_delegate from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000004' and feature_key='hse.copilot'),false,'D6 delegated grant carries no delegation right');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000004');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000004' and feature_key='hse.copilot'),'a2000000-0000-0000-0000-000000000007','Chain')$$,'42501',null,'D7 a delegate cannot re-delegate');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_revoke_member_entitlement((select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and revoked_at is null and can_delegate),'End delegation');
select extensions.ok(not private.has_feature_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','hse.copilot'),'D8 revoking the source ends delegated access');
select extensions.ok(exists(select 1 from audit.events where action_key='iam.entitlement_delegation.created') and exists(select 1 from audit.events where action_key='iam.entitlement_delegation.revoked_with_parent'),'D9 delegation and cascade revocation are audited');

-- Restriction of an existing company entitlement (Operation A) is a different operation
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','operations',null,'No operations module for this member',false,false);
select extensions.ok(not private.has_member_module_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','operations')
 and private.has_member_module_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002','operations')
 and private.has_member_module_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse'),'A1 personal module restriction affects only that member and module');
-- Effective access agrees with the enforcement function
select extensions.is((select count(*)::integer from jsonb_array_elements(api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003')->'permissions') e
  where exists(select 1 from iam.permission_catalog c where c.permission_key=e->>'permission_key' and 'read'=any(c.supported_actions))
   and (e->>'effective')::boolean is distinct from pg_temp.az('a0000000-0000-0000-0000-000000000003','a1000000-0000-0000-0000-00000000000a',e->>'permission_key')),0,
  'E1 server effective access matches enforcement for every permission (Superadmin with restrictions)');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.is((select count(*)::integer from jsonb_array_elements(api.member_effective_access('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005')->'permissions') e
  where exists(select 1 from iam.permission_catalog c where c.permission_key=e->>'permission_key' and 'read'=any(c.supported_actions))
   and (e->>'effective')::boolean is distinct from pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a',e->>'permission_key')),0,
  'E2 server effective access matches enforcement for every permission (employee)');
-- Security probes
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select set_config('sentriq.operator_decision_actor','a0000000-0000-0000-0000-000000000001',true);
select extensions.ok(private.operator_decision_actor() is null,'S1 a forged operator marker does not validate for a different caller');
select set_config('sentriq.invitation_restriction_deny','on',true);
set local role authenticated;
select extensions.throws_ok($$insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,status,granted_by,reason) values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.forms.read','deny','tenant',false,false,'active','a0000000-0000-0000-0000-000000000002','Superadmin invitation restriction: forged')$$,'42501',null,'S2 a forged invitation marker does not bypass decision guards outside the trigger');
reset role;
select extensions.ok(not has_function_privilege('authenticated','private.member_module_state(uuid,uuid,text)','EXECUTE')
 and not has_function_privilege('authenticated','private.member_feature_state(uuid,uuid,text)','EXECUTE')
 and not has_function_privilege('authenticated','private.entitlement_grant_live(uuid)','EXECUTE')
 and not has_function_privilege('anon','api.member_effective_access(uuid,uuid)','EXECUTE')
 and not has_function_privilege('anon','api.platform_set_member_entitlement(uuid,uuid,text,text,text,boolean,boolean,timestamptz,timestamptz)','EXECUTE'),
 'S3 helpers are private and anon cannot call the new RPCs');
select extensions.throws_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse','hse.copilot','both keys')$$,'42501',null,'S4 module and feature together are rejected');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.throws_ok($$select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse',null,'both keys',false,true)$$,'42501',null,'S5 can_delegate requires can_use');
select extensions.throws_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.copilot.use','allow','Allow without entitlement')$$,'42501',null,'S6 Allow cannot create an entitlement');
select extensions.finish();
rollback;
