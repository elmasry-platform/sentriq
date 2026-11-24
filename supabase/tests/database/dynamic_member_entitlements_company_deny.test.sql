-- Acceptance tests for dynamic member permissions and individual entitlement overrides.
begin;
select extensions.plan(19);
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

insert into core.sites(id,tenant_id,name,code) values('a3000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-00000000000a','Site 1','S1');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by,active)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','a3000000-0000-0000-0000-000000000001','a0000000-0000-0000-0000-000000000002',true);
create or replace function pg_temp.flag(p boolean) returns void language sql as $$ select set_config('sentriq.migration_runner',case when p then 'on' else 'off' end,true) $$;
create or replace function pg_temp.sa_deny(p_uid uuid) returns uuid language plpgsql as $$
begin perform pg_temp.as_user(p_uid);
 return api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','deny','tenant',null,null,null,null,false,false,null,null,'Company Deny'); end $$;

-- C1: a Deny placed by Superadmin 2 belongs to Superadmin 2
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select extensions.lives_ok($$select pg_temp.sa_deny('a0000000-0000-0000-0000-000000000002')$$,'C1 Superadmin 2 places a Deny on an employee');
reset role;
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a','hse.dashboard.read'),'C1 the Deny is in force');
reset role;
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
set local role authenticated;
select extensions.throws_ok($$select api.clear_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','Other Superadmin clears')$$,'42501',null,'C2 another Superadmin cannot clear it');
select extensions.throws_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','tenant',null,null,null,null,true,true,null,null,'Other Superadmin replaces')$$,'42501',null,'C3 another Superadmin cannot replace it with an Allow');
select extensions.throws_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','deny','tenant',null,null,null,null,false,false,null,null,'Other Superadmin re-denies')$$,'42501',null,'C3 nor with their own Deny');
-- the same with triggers bypassed: the RPC bodies refuse on their own
reset role;
select pg_temp.flag(true);
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
select extensions.throws_ok($$select api.clear_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','RPC body check')$$,'42501',null,'C4 the clear RPC body refuses (triggers bypassed)');
select extensions.throws_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','tenant',null,null,null,null,true,true,null,null,'RPC body check')$$,'42501',null,'C4 the set RPC body refuses (triggers bypassed)');
select pg_temp.flag(false);
-- specific_override: only the Deny's owner can make an effective one
select pg_temp.flag(true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,can_read,can_write,exception_kind,status,granted_by,reason)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','site','a3000000-0000-0000-0000-000000000001',true,true,'specific_override','active','a0000000-0000-0000-0000-000000000003','Override by another Superadmin');
select pg_temp.flag(false);
select pg_temp.as_user('a0000000-0000-0000-0000-000000000005');
select extensions.ok(not api.authorize('a1000000-0000-0000-0000-00000000000a','hse.dashboard.read','read','a3000000-0000-0000-0000-000000000001'),'C5 a specific_override made by another Superadmin does not lift the Deny');
reset role;
reset role;

-- C6: the setter can replace and clear
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
set local role authenticated;
select extensions.lives_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','deny','tenant',null,null,null,null,false,false,null,null,'Setter re-denies')$$,'C6 the setter can replace their own Deny');
select extensions.lives_ok($$select api.clear_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','Setter clears')$$,'C6 the setter can clear their own Deny');
reset role;
-- C7: a specific_override made by the setter still works against the setter's own Deny
select pg_temp.flag(true);
update iam.member_permission_decisions set status='revoked',revoked_at=now(),revoked_by='a0000000-0000-0000-0000-000000000002',revoke_reason='fixture' where permission_key='hse.dashboard.read' and exception_kind='specific_override';
select pg_temp.flag(false);
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select pg_temp.sa_deny('a0000000-0000-0000-0000-000000000002');
reset role;
select pg_temp.flag(true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,can_read,can_write,exception_kind,status,granted_by,reason)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','site','a3000000-0000-0000-0000-000000000001',true,true,'specific_override','active','a0000000-0000-0000-0000-000000000002','Override by the setter');
select pg_temp.flag(false);
select pg_temp.as_user('a0000000-0000-0000-0000-000000000005');
select extensions.ok(api.authorize('a1000000-0000-0000-0000-00000000000a','hse.dashboard.read','read','a3000000-0000-0000-0000-000000000001') and not api.authorize('a1000000-0000-0000-0000-00000000000a','hse.dashboard.read','read'),
 'C7 the setter keeps the existing specific_override behaviour for their own Deny');
reset role;

-- C8: Subowner (member.permissions) and Owner can remove it
select pg_temp.as_user('a0000000-0000-0000-0000-000000000009');
set local role authenticated;
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','default','Subowner clears a company Deny')$$,'C8 a Subowner holding member.permissions can clear it');
reset role;
select extensions.ok(not exists(select 1 from iam.member_permission_decisions where membership_id='a2000000-0000-0000-0000-000000000005' and permission_key='hse.dashboard.read' and decision='deny' and status='active'),'C8 the Deny is gone');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select pg_temp.sa_deny('a0000000-0000-0000-0000-000000000002');
reset role;
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
set local role authenticated;
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','default','Owner clears a company Deny')$$,'C8 the Owner can clear it');
reset role;
-- a Subowner without the power cannot
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select pg_temp.sa_deny('a0000000-0000-0000-0000-000000000002');
reset role;
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.set_subowner_platform_permission('a0000000-0000-0000-0000-000000000009','member.permissions',false,'Withdraw');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000009');
select extensions.throws_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','default','Subowner without the power')$$,'42501',null,'C8 a Subowner without member.permissions cannot clear it');
reset role;

-- C9: the setter is suspended: the Deny stays and only Subowner or Owner can clear it
select pg_temp.flag(true);
update iam.memberships set status='suspended' where id='a2000000-0000-0000-0000-000000000002';
select pg_temp.flag(false);
select extensions.ok(exists(select 1 from iam.member_permission_decisions where membership_id='a2000000-0000-0000-0000-000000000005' and permission_key='hse.dashboard.read' and decision='deny' and status='active'),'C9 the Deny stays active after its setter is suspended');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
set local role authenticated;
select extensions.throws_ok($$select api.clear_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','Take over')$$,'42501',null,'C9 a remaining Superadmin cannot clear it');
select extensions.throws_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','tenant',null,null,null,null,true,true,null,null,'Take over')$$,'42501',null,'C9 nor replace it');
reset role;
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
set local role authenticated;
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.dashboard.read','default','Owner approves the change')$$,'C9 the Owner can clear it');
reset role;
select extensions.finish();
rollback;
