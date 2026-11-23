begin;
select extensions.plan(30);
create temporary table completion_assertions(line text);
grant insert,select on table pg_temp.completion_assertions to authenticated;

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000101','authenticated','authenticated','completion-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000102','authenticated','authenticated','completion-superadmin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000103','authenticated','authenticated','completion-operator@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000104','authenticated','authenticated','completion-admin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000105','authenticated','authenticated','completion-employee@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000106','authenticated','authenticated','completion-new-superadmin@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000101');
insert into iam.platform_operators(user_id,operator_role,created_by)
 values('00000000-0000-0000-0000-000000000103','subowner','00000000-0000-0000-0000-000000000101');
insert into core.tenants(id,name,created_by) values
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','Completion A','00000000-0000-0000-0000-000000000101'),
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeb01','Completion B','00000000-0000-0000-0000-000000000101');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-00000000e102','eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','00000000-0000-0000-0000-000000000102','company_superadmin','active','completion-superadmin@example.test'),
 ('10000000-0000-0000-0000-00000000e104','eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','00000000-0000-0000-0000-000000000104','company_admin','active','completion-admin@example.test'),
 ('10000000-0000-0000-0000-00000000e105','eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','00000000-0000-0000-0000-000000000105','employee','active','completion-employee@example.test'),
 ('10000000-0000-0000-0000-00000000eb05','eeeeeeee-eeee-eeee-eeee-eeeeeeeeeb01','00000000-0000-0000-0000-000000000105','employee','active','completion-employee@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by) values
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','hse','active','00000000-0000-0000-0000-000000000101'),
 ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeb01','hse','active','00000000-0000-0000-0000-000000000101');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
select tenant_id,module_key,created_at,'infinity'::timestamptz,changed_by,'Phase 1 permission completion test','complimentary','legacy_backfill',id
from core.tenant_entitlements where tenant_id in ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','eeeeeeee-eeee-eeee-eeee-eeeeeeeeeb01');

insert into iam.roles(id,tenant_id,role_key,label,role_family,created_by)
 values('60000000-0000-0000-0000-00000000e101','eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','completion_employee','Completion Employee','employee','00000000-0000-0000-0000-000000000101');
insert into iam.role_versions(id,tenant_id,role_id,version_no,role_family,status,created_by,published_at)
 values('61000000-0000-0000-0000-00000000e101','eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','60000000-0000-0000-0000-00000000e101',1,'employee','published','00000000-0000-0000-0000-000000000101',now());
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read)
 values('61000000-0000-0000-0000-00000000e101','view_all','tenant',true);
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;

create temporary table completion_superadmin_invite(invitation_id uuid,token text) on commit drop;
grant insert,select on table pg_temp.completion_superadmin_invite to authenticated;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000102',true);
set local role authenticated;

insert into completion_assertions(line) select extensions.lives_ok($$select * from api.set_default_permission_profile(
 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','employee','Default Employee',
 '[{"permission_key":"view_all","scope_kind":"tenant","can_read":true,"can_write":false}]'::jsonb,
 'new_users_only','{}'::uuid[],'Initial employee default')$$,'Company Superadmin can create a versioned default profile');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.permission_profile_defaults where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and role_family='employee'),1,'new-user profile default is recorded independently');
insert into completion_assertions(line) select extensions.lives_ok($$select * from api.set_default_permission_profile(
 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','employee','Selected Employees',
 '[{"permission_key":"view_all","scope_kind":"tenant","can_read":true,"can_write":false}]'::jsonb,
 'selected_existing_users',array['10000000-0000-0000-0000-00000000e105'::uuid],'Apply only to the selected employee')$$,'Superadmin can apply a profile to an explicitly selected existing employee');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.membership_permission_profiles where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and membership_id='10000000-0000-0000-0000-00000000e105' and is_current),1,'selected employee receives one current profile');
insert into completion_assertions(line) select extensions.is((select d.profile_version_id=(select pv.id from iam.permission_profile_versions pv where pv.tenant_id=d.tenant_id and pv.profile_id=d.profile_id and pv.version_no=1) from iam.permission_profile_defaults d where d.tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and d.role_family='employee'),true,'selected-existing-only change preserves the future-user default');
insert into completion_assertions(line) select extensions.is((select p.current_version from iam.permission_profiles p where p.tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and p.role_family='employee'),2,'profile metadata advances to the newest immutable version');
insert into completion_assertions(line) select extensions.throws_ok($$insert into iam.permission_profile_defaults(tenant_id,role_family,profile_id,profile_version_id,updated_by) values('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','employee',gen_random_uuid(),gen_random_uuid(),auth.uid())$$,'42501',null,'authenticated callers cannot write profile defaults directly');
insert into completion_assertions(line) select extensions.throws_ok($$update iam.permission_profile_versions set version_no=version_no+1 where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01'$$,'42501',null,'profile version history is immutable');
insert into completion_assertions(line) select extensions.throws_ok($$insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,granted_by,reason) values('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','view_all','deny','tenant',auth.uid(),'Direct table write denied')$$,'42501',null,'authenticated callers cannot write direct decisions through table DML');
insert into completion_assertions(line) select extensions.lives_ok($$select api.set_member_permission_decision('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','view_all','deny','tenant',null,null,null,null,false,false,null,null,'Explicit employee deny')$$,'Superadmin can record an audited direct deny');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.member_permission_decisions where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and membership_id='10000000-0000-0000-0000-00000000e105' and decision='deny' and status='active'),1,'direct deny is stored for the exact employee');
insert into completion_assertions(line) select extensions.throws_ok($$select api.set_member_permission_decision('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000eb05','view_all','deny','tenant',null,null,null,null,false,false,null,null,'Cross tenant')$$,'22023',null,'permission decision cannot target a membership in another tenant');
insert into completion_assertions(line) select extensions.throws_ok($$select api.set_member_permission_decision('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','view_all','allow','tenant',null,null,null,null,true,false,now()-interval '1 minute',null,'Expired allow')$$,'23514',null,'expired permission decisions are rejected by the database constraint');

insert into completion_assertions(line) select extensions.lives_ok($$select api.assign_membership_role('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','60000000-0000-0000-0000-00000000e101','61000000-0000-0000-0000-00000000e101','{}'::uuid[],'{}'::uuid[],now(),null,'Assign employee role')$$,'Company Superadmin can assign a matching published Employee role');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.membership_roles where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and membership_id='10000000-0000-0000-0000-00000000e105' and role_version_id='61000000-0000-0000-0000-00000000e101' and revoked_at is null),1,'role assignment is tenant-bound and versioned');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000103',true);
insert into completion_assertions(line) select extensions.throws_ok($$select api.assign_membership_role('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','60000000-0000-0000-0000-00000000e101','61000000-0000-0000-0000-00000000e101','{}'::uuid[],'{}'::uuid[],now(),null,'Platform cannot assign company role')$$,'42501',null,'Platform Subowner identity alone cannot assign a tenant role');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.permission_profiles where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01'),0,'Platform Subowner cannot read tenant permission profiles');

select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000102',true);
insert into completion_assertions(line) select extensions.lives_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','new-employee@example.test','employee',interval '7 days')$$,'Company Superadmin can invite an Employee through the authenticated API');
insert into completion_assertions(line) select extensions.throws_ok($$select * from api.create_company_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','admin-forbidden@example.test','company_superadmin',interval '7 days')$$,'42501',null,'Company Superadmin cannot invite another Company Superadmin');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000101',true);
select api.set_subowner_platform_permission('00000000-0000-0000-0000-000000000103','superadmin.invite',true,'Owner approves test invitation');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000103',true);
insert into completion_superadmin_invite(invitation_id,token)
 select invitation_id,token from api.create_company_superadmin_invitation(
  'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeb01','completion-new-superadmin@example.test',interval '7 days',
  '[{"permission_key":"hse.copilot.use","can_use":false,"can_delegate":false,"reason":"Copilot disabled by platform"},{"permission_key":"role_assignment","can_use":true,"can_delegate":false,"reason":"Role delegation disabled by platform"}]'::jsonb,
  'Restricted Company Superadmin invitation');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from jsonb_array_elements(api.platform_read_company('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeb01','iam.superadmin_invitation_limits')->'rows') item where item->>'invitation_id' is not null),2,'Platform Operator records invitation-level capability restrictions before acceptance');
reset role;
select api.accept_invitation((select token from completion_superadmin_invite),'00000000-0000-0000-0000-000000000106');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.superadmin_capability_limits l join iam.memberships m on m.tenant_id=l.tenant_id and m.id=l.membership_id where m.user_id='00000000-0000-0000-0000-000000000106' and l.capability_key in ('hse.copilot.use','role_assignment') and not l.can_delegate),2,'accepted Superadmin inherits the invitation restriction envelope');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.superadmin_invitation_limits l join iam.memberships m on m.tenant_id=l.tenant_id and m.id=l.membership_id where m.user_id='00000000-0000-0000-0000-000000000106' and l.invitation_id is null),2,'accepted invitation restrictions are detached from the consumed invite');

select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000102',true);
set local role authenticated;
insert into completion_assertions(line) select extensions.throws_ok($$select api.set_superadmin_capability_limit('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e102','hse.copilot.use',false,false,'Company cannot set platform restrictions')$$,'42501',null,'Company Superadmin cannot change platform-owned capability limits');
insert into completion_assertions(line) select extensions.lives_ok($$select api.create_delegation('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e104','tenant',null,null,array['role_assignment','direct_permission_decision'],'now()',null,'Delegate two company capabilities')$$,'Company Superadmin can delegate a bounded tenant envelope');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.delegation_envelopes where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and delegate_membership_id='10000000-0000-0000-0000-00000000e104' and status='active'),1,'delegation envelope is recorded against the selected Admin');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000104',true);
insert into completion_assertions(line) select extensions.lives_ok($$select api.create_delegation('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','tenant',null,null,array['role_assignment'],'now()',null,'Delegate within parent capability')$$,'Admin can create a child delegation within the parent envelope');
insert into completion_assertions(line) select extensions.throws_ok($$select api.create_delegation('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01','10000000-0000-0000-0000-00000000e105','tenant',null,null,array['permissions.specific_override'],'now()',null,'Attempt to exceed parent capability')$$,'42501',null,'delegated Admin cannot expand capability beyond the parent envelope');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000102',true);
insert into completion_assertions(line) select extensions.is(api.revoke_delegation('eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01',(select id from iam.delegation_envelopes where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and delegate_membership_id='10000000-0000-0000-0000-00000000e104'),'Revoke parent and descendants'),2,'revoking the parent atomically revokes the child envelope');
insert into completion_assertions(line) select extensions.is((select count(*)::integer from iam.delegation_review_events where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01' and action='revoke'),1,'revocation review history is appended for the root envelope');
insert into completion_assertions(line) select extensions.throws_ok($$delete from iam.delegation_review_events where tenant_id='eeeeeeee-eeee-eeee-eeee-eeeeeeeeea01'$$,'42501',null,'authenticated callers cannot delete delegation review history');

select line from completion_assertions;
select * from extensions.finish();
rollback;
