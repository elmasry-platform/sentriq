-- Acceptance tests for dynamic member permissions and individual entitlement overrides.
begin;
select extensions.plan(25);
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

-- Site for scoped overrides.
insert into core.sites(id,tenant_id,name,code) values('a3000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-00000000000a','Site 1','S1');

-- R1/R2: operator-origin Deny is protected
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse.forms.manage','deny','Operator restriction');
select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.inspections.create','deny','Operator restriction');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
set local role authenticated;
select extensions.throws_ok($$select api.clear_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse.forms.manage','Clear my own restriction')$$,'42501',null,'R1 a Superadmin cannot clear a Deny on their own membership');
reset role;
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
set local role authenticated;
select extensions.throws_ok($$select api.clear_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse.forms.manage','Clear operator deny')$$,'42501',null,'R1 a Superadmin cannot clear an operator-origin Deny');
select extensions.throws_ok($$select api.set_member_permission_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.inspections.create','allow','tenant',null,null,null,null,true,true,null,null,'Overwrite operator deny')$$,'42501',null,'R2 a Superadmin cannot overwrite an operator-origin Deny with Allow');
reset role;
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000003','a1000000-0000-0000-0000-00000000000a','hse.forms.manage')
  and not pg_temp.az('a0000000-0000-0000-0000-000000000005','a1000000-0000-0000-0000-00000000000a','hse.inspections.create'),'R1/R2 both operator Denies still enforce');
-- specific_override vs tenant Deny
reset role;
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,can_read,can_write,exception_kind,status,granted_by,reason)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse.forms.manage','allow','site','a3000000-0000-0000-0000-000000000001',true,true,'specific_override','active','a0000000-0000-0000-0000-000000000002','Override attempt');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
select extensions.ok(not api.authorize('a1000000-0000-0000-0000-00000000000a','hse.forms.manage','read','a3000000-0000-0000-0000-000000000001'),
 'R2 a specific_override cannot bypass an operator-origin tenant Deny (read)');
select extensions.ok(not api.authorize('a1000000-0000-0000-0000-00000000000a','hse.forms.manage','write','a3000000-0000-0000-0000-000000000001'),
 'R2 a specific_override cannot bypass an operator-origin tenant Deny (write)');
-- control: an ordinary company Deny can still be overridden at a site by specific_override
reset role;
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,status,granted_by,reason)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002','hse.dashboard.read','deny','tenant',false,false,'active','a0000000-0000-0000-0000-000000000003','Company deny');
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,can_read,can_write,exception_kind,status,granted_by,reason)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002','hse.dashboard.read','allow','site','a3000000-0000-0000-0000-000000000001',true,true,'specific_override','active','a0000000-0000-0000-0000-000000000003','Site override');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000002');
select extensions.ok(api.authorize('a1000000-0000-0000-0000-00000000000a','hse.dashboard.read','read','a3000000-0000-0000-0000-000000000001')
  and not api.authorize('a1000000-0000-0000-0000-00000000000a','hse.dashboard.read','read'),
 'R2 control: a company Deny keeps its existing specific_override behaviour');
reset role;
delete from iam.member_permission_decisions where membership_id='a2000000-0000-0000-0000-000000000002' and permission_key='hse.dashboard.read';

-- R5: a Deny does not depend on the liveness of its source envelope
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
insert into iam.delegation_envelopes(id,tenant_id,grantor_membership_id,delegate_membership_id,level,allowed_capabilities,status,created_by,revoked_at,revoked_by,revoke_reason)
values('a4000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','a2000000-0000-0000-0000-000000000004','tenant',array['direct_permission_decision'],'revoked','a0000000-0000-0000-0000-000000000003',now(),'a0000000-0000-0000-0000-000000000003','ended');
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,status,granted_by,reason,source_delegation_id)
values('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002','hse.dashboard.read','deny','tenant',false,false,'active','a0000000-0000-0000-0000-000000000004','Deny from an ended envelope','a4000000-0000-0000-0000-000000000001');
select extensions.ok(not pg_temp.az('a0000000-0000-0000-0000-000000000002','a1000000-0000-0000-0000-00000000000a','hse.dashboard.read'),
 'R5 a Deny stays enforced after its delegation envelope ended');
reset role;
delete from iam.member_permission_decisions where membership_id='a2000000-0000-0000-0000-000000000002' and permission_key='hse.dashboard.read';

-- R3: Subowner powers on membership-scoped entitlement rows
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002','operations',null,'Owner restriction',false,false);
select pg_temp.as_user('a0000000-0000-0000-0000-000000000009');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.set_subowner_platform_permission('a0000000-0000-0000-0000-000000000009','member.permissions',false,'Withdraw');
select api.set_subowner_platform_permission('a0000000-0000-0000-0000-000000000009','member.entitlements',false,'Withdraw');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000009');
select extensions.throws_ok($$select api.issue_entitlement_grant('a1000000-0000-0000-0000-00000000000a',null,'hse.copilot','a2000000-0000-0000-0000-000000000005',now(),now()+interval '10 days','Back door','platform_absorbed',null,null,null)$$,'42501',null,'R3 a Subowner without member.entitlements cannot issue a personal grant via the legacy RPC');
select extensions.throws_ok($$select api.set_entitlement_grant_status((select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000002' and module_key='operations' and not can_use),'suspended','Lift restriction')$$,'42501',null,'R3 a Subowner without member.entitlements cannot suspend a restriction');
select extensions.throws_ok($$select api.revoke_entitlement_grant((select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000002' and module_key='operations' and not can_use),'Lift restriction')$$,'42501',null,'R3 a Subowner without member.entitlements cannot revoke a personal grant via the legacy RPC');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select extensions.throws_ok($$select api.set_entitlement_grant_status((select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000002' and module_key='operations' and not can_use),'suspended','Suspend restriction')$$,'42501',null,'R3 even the Owner cannot lift a restriction by suspending it (revoke it instead)');
select extensions.ok(not private.has_member_module_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000002','operations'),'R3 the restriction is still enforced');

-- R4/R7: restricting the source holder ends delegated access
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005',null,'hse.copilot','Delegating lead',true,true,now(),now()+interval '10 days');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000005');
select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and can_delegate and revoked_at is null),'a2000000-0000-0000-0000-000000000004','Share');
select extensions.ok(private.has_feature_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','hse.copilot'),'R4 control: the delegate has the feature');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005',null,'hse.copilot','Restrict the holder',false,false);
select extensions.ok(not private.has_feature_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','hse.copilot'),'R4 a restricted source holder no longer passes access on to existing delegates');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000005');
select extensions.throws_ok($$select api.delegate_member_entitlement('a1000000-0000-0000-0000-00000000000a',(select id from core.entitlement_grants where membership_id='a2000000-0000-0000-0000-000000000005' and feature_key='hse.copilot' and can_delegate and revoked_at is null),'a2000000-0000-0000-0000-000000000006','Share while restricted')$$,'42501',null,'R4 a restricted holder cannot delegate');
-- usage recording must not pick the non-live delegated grant
reset role;
insert into core.entitlement_grants(id,tenant_id,feature_key,starts_at,granted_by,reason,billing_treatment)
values('a5000000-0000-0000-0000-000000000001','a1000000-0000-0000-0000-00000000000a','hse.copilot',now()-interval '1 day','a0000000-0000-0000-0000-000000000001','Company copilot','complimentary');
select set_config('request.jwt.claim.role','service_role',true);
select api.record_feature_usage('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','hse.copilot','dme-usage-key-0001',1,(select usage_unit from core.features where feature_key='hse.copilot'));
select extensions.is((select grant_id from core.usage_events where idempotency_key='dme-usage-key-0001'),'a5000000-0000-0000-0000-000000000001'::uuid,'R7 usage is attributed to a live grant, not a non-live delegated one');

-- R8: member-aware module check in create_delegation and create_company_invitation
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
select extensions.lives_ok($$select api.create_delegation('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','tenant',null,null,array['direct_permission_decision'],now(),null,'control delegation')$$,'R8 control: an unrestricted Superadmin can delegate');
select extensions.lives_ok($$select api.create_company_invitation('a1000000-0000-0000-0000-00000000000a','ctl@example.test','employee')$$,'R8 control: an unrestricted Superadmin can invite');
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
select api.platform_set_member_entitlement('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000003','hse',null,'Restrict module',false,false);
select pg_temp.as_user('a0000000-0000-0000-0000-000000000003');
select extensions.throws_ok($$select api.create_delegation('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000004','tenant',null,null,array['direct_permission_decision'],now(),null,'restricted delegation')$$,null,null,'R8 a member restricted from the module cannot create a delegation');
select extensions.throws_ok($$select api.create_company_invitation('a1000000-0000-0000-0000-00000000000a','blocked@example.test','employee')$$,'42501',null,'R8 a member restricted from the module cannot invite');

-- R12: the operator RPC still works under the real (non-bypass) role, including clearing a protected Deny
reset role;
select pg_temp.as_user('a0000000-0000-0000-0000-000000000001');
set local role authenticated;
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.inspections.create','default','Operator clears its own Deny')$$,'R12 the operator can clear a protected Deny');
select extensions.lives_ok($$select api.platform_set_member_decision('a1000000-0000-0000-0000-00000000000a','a2000000-0000-0000-0000-000000000005','hse.inspections.create','deny','Operator denies again')$$,'R12 the operator can set a Deny under the real role');
reset role;
select extensions.ok((select protected_origin from iam.member_permission_decisions where membership_id='a2000000-0000-0000-0000-000000000005' and permission_key='hse.inspections.create' and status='active'),'R12 operator Denies are marked protected');

-- R11
reset role;
select extensions.ok(not has_function_privilege('authenticated','private.people_scope_allowed(uuid,uuid,uuid,uuid)','EXECUTE'),'R11 people_scope_allowed is not callable by authenticated');
select extensions.finish();
rollback;
