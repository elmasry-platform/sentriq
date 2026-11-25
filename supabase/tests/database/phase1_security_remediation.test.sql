begin;
select extensions.plan(14);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000101','authenticated','authenticated','phase1-remediation-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000102','authenticated','authenticated','phase1-remediation-superadmin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000103','authenticated','authenticated','phase1-remediation-operator@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000104','authenticated','authenticated','phase1-audit-admin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000105','authenticated','authenticated','phase1-audit-employee@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000101');
insert into iam.platform_operators(user_id,operator_role,created_by)
 values('00000000-0000-0000-0000-000000000103','subowner','00000000-0000-0000-0000-000000000101');
insert into core.tenants(id,name,created_by) values
 ('cccccccc-cccc-cccc-cccc-ccccccccca01','Remediation A','00000000-0000-0000-0000-000000000101'),
 ('dddddddd-dddd-dddd-dddd-dddddddddb01','Remediation B','00000000-0000-0000-0000-000000000101');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-00000000c104','cccccccc-cccc-cccc-cccc-ccccccccca01','00000000-0000-0000-0000-000000000104','company_superadmin','active','phase1-audit-admin@example.test'),
 ('10000000-0000-0000-0000-00000000d104','dddddddd-dddd-dddd-dddd-dddddddddb01','00000000-0000-0000-0000-000000000104','company_superadmin','active','phase1-audit-admin@example.test'),
 ('10000000-0000-0000-0000-00000000c105','cccccccc-cccc-cccc-cccc-ccccccccca01','00000000-0000-0000-0000-000000000105','employee','active','phase1-audit-employee@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by) values
 ('cccccccc-cccc-cccc-cccc-ccccccccca01','hse','active','00000000-0000-0000-0000-000000000101'),
 ('dddddddd-dddd-dddd-dddd-dddddddddb01','hse','active','00000000-0000-0000-0000-000000000101');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
select tenant_id,module_key,created_at,'infinity'::timestamptz,changed_by,'Phase 1 remediation test','complimentary','legacy_backfill',id
from core.tenant_entitlements where tenant_id in ('cccccccc-cccc-cccc-cccc-ccccccccca01','dddddddd-dddd-dddd-dddd-dddddddddb01');
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000104',true);
insert into core.org_units(id,tenant_id,name) values
 ('20000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','Remediation A Unit'),
 ('20000000-0000-0000-0000-00000000d101','dddddddd-dddd-dddd-dddd-dddddddddb01','Remediation B Unit');
insert into core.sites(id,tenant_id,org_unit_id,name,code) values
 ('30000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','20000000-0000-0000-0000-00000000c101','Remediation A Site','RA01'),
 ('30000000-0000-0000-0000-00000000c102','cccccccc-cccc-cccc-cccc-ccccccccca01','20000000-0000-0000-0000-00000000c101','Remediation A Other Site','RA02'),
 ('30000000-0000-0000-0000-00000000d101','dddddddd-dddd-dddd-dddd-dddddddddb01','20000000-0000-0000-0000-00000000d101','Remediation B Site','RB01');
insert into hse.people(id,tenant_id,display_name,person_kind,created_by) values
 ('40000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','Remediation Person','employee','00000000-0000-0000-0000-000000000104');
insert into hse.contractor_organizations(id,tenant_id,name,created_by) values
 ('41000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','Remediation Contractor','00000000-0000-0000-0000-000000000104');
insert into hse.person_engagements(id,tenant_id,person_id,engagement_type,site_id,org_unit_id,created_by) values
 ('50000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','40000000-0000-0000-0000-00000000c101','employee','30000000-0000-0000-0000-00000000c101','20000000-0000-0000-0000-00000000c101','00000000-0000-0000-0000-000000000104');

-- Create a legacy unversioned employee assignment with a positive legacy grant.
insert into iam.roles(id,tenant_id,role_key,label,role_family,created_by)
 values('60000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','audit_employee','Audit employee','employee','00000000-0000-0000-0000-000000000104');
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,active)
 values('60000000-0000-0000-0000-00000000c101','view_all','tenant',true,true);
insert into iam.role_versions(id,tenant_id,role_id,version_no,role_family,status,created_by,published_at)
 values('61000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','60000000-0000-0000-0000-00000000c101',1,'employee','published','00000000-0000-0000-0000-000000000104',now());
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read)
 values('61000000-0000-0000-0000-00000000c101','view_all','tenant',true);
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;
alter table iam.membership_roles disable trigger membership_role_tenant_guard;
insert into iam.membership_roles(id,tenant_id,membership_id,role_id,role_version_id,granted_by)
 values('62000000-0000-0000-0000-00000000c101','cccccccc-cccc-cccc-cccc-ccccccccca01','10000000-0000-0000-0000-00000000c105','60000000-0000-0000-0000-00000000c101',null,'00000000-0000-0000-0000-000000000104');
alter table iam.membership_roles enable trigger membership_role_tenant_guard;

select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000103',true);
set local role authenticated;
select extensions.ok(not private.can_manage_tenant('cccccccc-cccc-cccc-cccc-ccccccccca01'),'Platform Subowner does not satisfy company tenant management');
select extensions.throws_ok($$insert into iam.roles(tenant_id,role_key,label,role_family,created_by) values('cccccccc-cccc-cccc-cccc-ccccccccca01','operator_forbidden','Forbidden','admin',auth.uid())$$,'42501',null,'Platform Subowner cannot write company functional roles');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000104',true);
select extensions.ok(private.can_manage_tenant('cccccccc-cccc-cccc-cccc-ccccccccca01'),'Company Superadmin retains tenant role management');
select extensions.throws_ok($$insert into iam.roles(tenant_id,role_key,label,created_by) values('cccccccc-cccc-cccc-cccc-ccccccccca01','missing_family','Missing family',auth.uid())$$,'23514',null,'new tenant role requires an explicit Admin or Employee family');
select extensions.throws_ok($$insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by) values('cccccccc-cccc-cccc-cccc-ccccccccca01','10000000-0000-0000-0000-00000000c104','60000000-0000-0000-0000-00000000c101','61000000-0000-0000-0000-00000000c101',auth.uid())$$,'42501',null,'Employee functional role cannot be assigned to Company Superadmin');
select extensions.throws_ok($$update iam.membership_roles set role_version_id=null where id='62000000-0000-0000-0000-00000000c101'$$,'23514',null,'assignment cannot be changed to a missing published role version');
select extensions.throws_ok($$update hse.people set tenant_id='dddddddd-dddd-dddd-dddd-dddddddddb01' where id='40000000-0000-0000-0000-00000000c101'$$,'23514',null,'People tenant ownership is immutable even for a user in both tenants');
select extensions.throws_ok($$update hse.contractor_organizations set tenant_id='dddddddd-dddd-dddd-dddd-dddddddddb01' where id='41000000-0000-0000-0000-00000000c101'$$,'23514',null,'contractor tenant ownership is immutable');
select extensions.throws_ok($$update hse.person_engagements set tenant_id='dddddddd-dddd-dddd-dddd-dddddddddb01' where id='50000000-0000-0000-0000-00000000c101'$$,'23514',null,'engagement tenant ownership is immutable');
select extensions.throws_ok($$update core.sites set tenant_id='dddddddd-dddd-dddd-dddd-dddddddddb01' where id='30000000-0000-0000-0000-00000000c101'$$,'23514',null,'Site tenant ownership is immutable');
select extensions.throws_ok($$update core.org_units set tenant_id='dddddddd-dddd-dddd-dddd-dddddddddb01' where id='20000000-0000-0000-0000-00000000c101'$$,'23514',null,'organizational unit tenant ownership is immutable');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000105',true);
select extensions.is(private.phase1_permission_allowed('cccccccc-cccc-cccc-cccc-ccccccccca01','view_all',null,null,false),false,'legacy permission rows do not authorize an unversioned assignment');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000104',true);
reset role;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,granted_by,reason)
 values('cccccccc-cccc-cccc-cccc-ccccccccca01','10000000-0000-0000-0000-00000000c104','view_all','deny','tenant','00000000-0000-0000-0000-000000000104','Override binding test deny');
select set_config('sentriq.migration_runner','off',true);
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,can_read,exception_kind,granted_by,reason)
 values('cccccccc-cccc-cccc-cccc-ccccccccca01','10000000-0000-0000-0000-00000000c104','view_all','allow','site','30000000-0000-0000-0000-00000000c102',true,'specific_override','00000000-0000-0000-0000-000000000104','Unrelated override scope');
select set_config('sentriq.migration_runner','off',true);
set local role authenticated;
select extensions.ok(not private.phase1_permission_allowed('cccccccc-cccc-cccc-cccc-ccccccccca01','view_all','30000000-0000-0000-0000-00000000c101','20000000-0000-0000-0000-00000000c101',false),'unrelated-site override cannot bypass a tenant deny');
reset role;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,can_read,exception_kind,granted_by,reason)
 values('cccccccc-cccc-cccc-cccc-ccccccccca01','10000000-0000-0000-0000-00000000c104','view_all','allow','site','30000000-0000-0000-0000-00000000c101',true,'specific_override','00000000-0000-0000-0000-000000000104','Exact narrower site override');
select set_config('sentriq.migration_runner','off',true);
set local role authenticated;
select extensions.ok(private.phase1_permission_allowed('cccccccc-cccc-cccc-cccc-ccccccccca01','view_all','30000000-0000-0000-0000-00000000c101','20000000-0000-0000-0000-00000000c101',false),'specific override can narrow a tenant deny to its exact site');
reset role;
select * from extensions.finish();
rollback;
