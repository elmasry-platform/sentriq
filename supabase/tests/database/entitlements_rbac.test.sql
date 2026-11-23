create extension if not exists pgtap with schema extensions;
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
-- The transactional pgTAP harness grants temporary read access so actual-role
-- RPC calls can be checked against their resulting rows. These grants roll back.
grant usage on schema core,iam,audit to service_role;
grant select on all tables in schema core,iam,audit to service_role;
select extensions.plan(242);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000001','authenticated','authenticated','owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000002','authenticated','authenticated','admin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000003','authenticated','authenticated','employee@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000004','authenticated','authenticated','reviewer@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000005','authenticated','authenticated','other@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000006','authenticated','authenticated','task@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000007','authenticated','authenticated','subowner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000008','authenticated','authenticated','unverified@example.test','',null,'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000009','authenticated','authenticated','wrong@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000010','authenticated','authenticated','newtenant-admin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000011','authenticated','authenticated','reactivate@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000012','authenticated','authenticated','invited-bypass@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000013','authenticated','authenticated','suspended-bypass@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000014','authenticated','authenticated','tenant-b-second-employee@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000001');
insert into iam.platform_operators(user_id,operator_role,created_by) values('00000000-0000-0000-0000-000000000007','subowner','00000000-0000-0000-0000-000000000001');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Test Tenant A','00000000-0000-0000-0000-000000000001'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','Test Tenant B','00000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000002','company_superadmin','active','admin@example.test'),
 ('10000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000003','employee','active','employee@example.test'),
 ('10000000-0000-0000-0000-000000000003','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000004','employee','active','reviewer@example.test'),
 ('10000000-0000-0000-0000-000000000004','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','00000000-0000-0000-0000-000000000005','employee','active','other@example.test'),
 ('10000000-0000-0000-0000-000000000005','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000006','employee','active','task@example.test'),
 ('10000000-0000-0000-0000-000000000006','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000009','company_superadmin','suspended','wrong@example.test'),
 ('10000000-0000-0000-0000-000000000007','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','00000000-0000-0000-0000-000000000004','company_superadmin','active','reviewer@example.test'),
 ('10000000-0000-0000-0000-000000000008','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000011','employee','active','reactivate@example.test'),
 ('10000000-0000-0000-0000-000000000009','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000012','employee','invited','invited-bypass@example.test'),
 ('10000000-0000-0000-0000-000000000010','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000013','employee','suspended','suspended-bypass@example.test'),
 ('10000000-0000-0000-0000-000000000011','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','00000000-0000-0000-0000-000000000014','employee','active','tenant-b-second-employee@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse','active','00000000-0000-0000-0000-000000000001');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
select e.tenant_id,e.module_key,e.created_at,'infinity'::timestamptz,e.changed_by,'Synthetic compatibility backfill','complimentary','legacy_backfill',e.id
 from core.tenant_entitlements e where e.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and e.module_key='hse';
insert into core.org_units(id,tenant_id,name) values('20000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Unit A');
insert into core.org_units(id,tenant_id,name) values('20000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Unit B');
insert into core.sites(id,tenant_id,org_unit_id,name,code) values
 ('30000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','20000000-0000-0000-0000-000000000001','Site A','A'),
 ('30000000-0000-0000-0000-000000000003','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','20000000-0000-0000-0000-000000000002','Site A2','A2'),
 ('30000000-0000-0000-0000-000000000002','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',null,'Site B','B');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','30000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001');
insert into iam.roles(tenant_id,role_key,label,role_family,created_by) values
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','copilot_user','Copilot User','employee','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','task_reader','Task Reader','employee','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','org_reader','Org Unit Reader','employee','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','site_reader','Site Reader','employee','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','tenant_reader','Tenant Reader','employee','00000000-0000-0000-0000-000000000001'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','foreign_role','Foreign Role','employee','00000000-0000-0000-0000-000000000001');
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
select r.id,p.permission_key,p.scope_kind,p.can_read,p.can_write from iam.roles r join (values
 ('copilot_user','hse.copilot.use','tenant',true,false),
 ('task_reader','hse.inspections.read','assigned_task',true,false),
 ('site_reader','hse.findings.read','site',true,false),
 ('tenant_reader','hse.actions.read','tenant',true,false)) p(role_key,permission_key,scope_kind,can_read,can_write)
 on r.role_key=p.role_key and r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
select id,'hse.inspections.read','org_unit',true,false from iam.roles where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and role_key='org_reader';
insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by,published_at)
select tenant_id,id,1,role_family,'published','00000000-0000-0000-0000-000000000001',now()
 from iam.roles where tenant_id is not null;
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read,can_write)
select rv.id,rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write
 from iam.role_versions rv join iam.role_permissions rp on rp.role_id=rv.role_id;
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002',id,'00000000-0000-0000-0000-000000000001'
 from iam.roles where role_key in ('inspector','auditor') and tenant_id is null;
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
select r.tenant_id,'10000000-0000-0000-0000-000000000002',r.id,rv.id,'00000000-0000-0000-0000-000000000001'
 from iam.roles r join iam.role_versions rv on rv.tenant_id=r.tenant_id and rv.role_id=r.id and rv.version_no=1
 where r.role_key='copilot_user' and r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
select r.tenant_id,'10000000-0000-0000-0000-000000000003',r.id,rv.id,'00000000-0000-0000-0000-000000000001'
 from iam.roles r join iam.role_versions rv on rv.tenant_id=r.tenant_id and rv.role_id=r.id and rv.version_no=1
 where r.role_key='copilot_user' and r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
select r.tenant_id,'10000000-0000-0000-0000-000000000005',r.id,rv.id,'00000000-0000-0000-0000-000000000001'
 from iam.roles r join iam.role_versions rv on rv.tenant_id=r.tenant_id and rv.role_id=r.id and rv.version_no=1
 where r.role_key in ('task_reader','org_reader') and r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
select r.tenant_id,'10000000-0000-0000-0000-000000000005',r.id,rv.id,'00000000-0000-0000-0000-000000000001'
 from iam.roles r join iam.role_versions rv on rv.tenant_id=r.tenant_id and rv.role_id=r.id and rv.version_no=1
 where r.role_key in ('site_reader','tenant_reader') and r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by)
select mr.tenant_id,mr.id,'30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001'
 from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='site_reader';
insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by)
select mr.tenant_id,mr.id,'20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001'
 from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='org_reader';
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004',id,'00000000-0000-0000-0000-000000000001'
 from iam.roles where role_key='auditor' and tenant_id is null;
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by,starts_at,ends_at)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003',id,'00000000-0000-0000-0000-000000000001',now()-interval '2 days',now()-interval '1 day'
 from iam.roles where role_key='inspector' and tenant_id is null;

select extensions.ok(private.has_module_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse'),'legacy HSE entitlement still enables HSE');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot'),'HSE does not implicitly license Copilot');
select extensions.ok(not has_function_privilege('authenticated','private.has_module_entitlement(uuid,text)','EXECUTE'),'authenticated callers cannot query arbitrary module entitlement helper');
select extensions.ok(not has_function_privilege('authenticated','private.has_hse_permission(uuid,uuid,text,uuid,boolean,text,uuid)','EXECUTE'),'authenticated callers cannot query arbitrary membership permission helper');
select extensions.ok(not has_table_privilege('authenticated','iam.memberships','INSERT') and not has_table_privilege('authenticated','iam.memberships','UPDATE') and not has_table_privilege('authenticated','iam.memberships','DELETE'),'authenticated has no direct membership write grants');
select extensions.ok(not has_table_privilege('service_role','iam.memberships','INSERT') and not has_table_privilege('service_role','iam.memberships','UPDATE') and not has_table_privilege('service_role','iam.memberships','DELETE'),'service_role must use narrow lifecycle RPCs rather than direct membership table writes');
select extensions.ok(not has_table_privilege('anon','iam.memberships','INSERT') and not has_table_privilege('anon','iam.memberships','UPDATE') and not has_table_privilege('anon','iam.memberships','DELETE'),'anon has no direct membership write grants');
select extensions.throws_ok($$insert into core.entitlement_grants(tenant_id,module_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment) values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse','10000000-0000-0000-0000-000000000004',now(),now()+interval '1 day','00000000-0000-0000-0000-000000000001','Invalid member module grant','complimentary')$$,'23514',null,'table constraint rejects membership-scoped module grants');
set local role authenticated;
select extensions.throws_ok($$select api.issue_entitlement_grant('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse',null,'10000000-0000-0000-0000-000000000004',now(),now()+interval '1 day','Invalid member module grant','complimentary',null,null,null)$$,'22023',null,'grant RPC rejects membership-scoped module grants explicitly');
select extensions.lives_ok($$select api.issue_entitlement_grant('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',null,'hse.copilot','10000000-0000-0000-0000-000000000004',now()-interval '1 minute',now()+interval '1 day','Member feature exception','complimentary',null,null,null)$$,'grant RPC accepts a member-scoped feature exception');
reset role;
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'member-scoped feature grant does not activate its parent company module');
select extensions.ok(not private.has_feature_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','hse.copilot'),'member-scoped feature remains ineffective while parent module is absent');
set local role authenticated;
select api.issue_entitlement_grant('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse',null,null,now()-interval '1 minute',now()+interval '1 day','Active module test','complimentary',null,null,null);
reset role;
select extensions.ok(private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'active module grant enables the module');
select extensions.ok(private.has_feature_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','hse.copilot'),'member feature grant is effective once its company module is active');
select extensions.ok(not private.has_feature_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000011','hse.copilot'),'member feature grant does not leak to another tenant membership');
update core.entitlement_grants set status='suspended' where tenant_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' and module_key='hse';
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'suspended module grant denies access');
update core.entitlement_grants set status='active' where tenant_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' and module_key='hse';
select api.revoke_entitlement_grant((select id from core.entitlement_grants where tenant_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' and module_key='hse' and revoked_at is null),'Synthetic revoke test');
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'revoked module grant denies access');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse',now()+interval '1 day',now()+interval '2 days','00000000-0000-0000-0000-000000000001','Future module grant test','complimentary');
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'future module grant denies access');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse',now()-interval '2 days',now()-interval '1 day','00000000-0000-0000-0000-000000000001','Expired module grant test','complimentary');
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'expired module grant denies access');
update core.modules set enabled=false where module_key='hse';
select extensions.ok(not private.has_module_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse'),'globally disabled module denies otherwise entitled tenant');
update core.modules set enabled=true where module_key='hse';
select extensions.ok(exists(select 1 from audit.events where action_key='core.modules.update' and scope_kind='platform' and summary->'changed_fields' ? 'enabled'),'module availability switch is audited as a platform event');
insert into core.plans(id,plan_key,version,name,status,currency,price_minor)
 values('90000000-0000-0000-0000-000000000001','test_hse',1,'Synthetic HSE plan','active','USD',1);
insert into core.plan_entitlements(id,plan_id,module_key) values
 ('91000000-0000-0000-0000-000000000001','90000000-0000-0000-0000-000000000001','hse');
insert into core.subscriptions(id,tenant_id,plan_id,status,starts_at,current_period_start,current_period_end,created_by)
 values('92000000-0000-0000-0000-000000000001','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','90000000-0000-0000-0000-000000000001','active',now()-interval '1 day',now()-interval '1 day',now()+interval '30 days','00000000-0000-0000-0000-000000000001');
insert into core.subscription_items(tenant_id,subscription_id,plan_entitlement_id,unit_price_minor,currency,starts_at)
 values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','92000000-0000-0000-0000-000000000001','91000000-0000-0000-0000-000000000001',1,'USD',now()-interval '1 day');
select extensions.ok(private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'active subscription grants module in its current period');
update core.subscriptions set status='suspended' where id='92000000-0000-0000-0000-000000000001';
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'suspended subscription denies module access');
update core.subscriptions set status='canceled',canceled_at=now() where id='92000000-0000-0000-0000-000000000001';
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'canceled subscription denies module access');
update core.subscriptions set status='active',canceled_at=null,current_period_end=now()-interval '1 second' where id='92000000-0000-0000-0000-000000000001';
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'expired subscription period denies module access');
update core.subscriptions set current_period_end=now()+interval '30 days' where id='92000000-0000-0000-0000-000000000001';
select extensions.lives_ok($$select api.update_subscription_status('92000000-0000-0000-0000-000000000001','suspended')$$,'platform can suspend an active subscription');
create temp table replacement_subscription_capture(id uuid) on commit drop;
insert into replacement_subscription_capture select api.create_subscription(
 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','90000000-0000-0000-0000-000000000001',now()-interval '1 minute',now()+interval '30 days','USD',
 '[{"plan_entitlement_id":"91000000-0000-0000-0000-000000000001","unit_price_minor":1,"quantity":1}]'::jsonb);
select extensions.ok(private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'replacement subscription is effective while the old subscription is suspended');
update core.subscription_items set starts_at=now()+interval '1 day' where subscription_id=(select id from replacement_subscription_capture);
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'future-dated subscription item does not grant early access');
update core.subscription_items set starts_at=now()-interval '1 minute' where subscription_id=(select id from replacement_subscription_capture);
update core.subscription_items set ends_at=now()-interval '1 second' where subscription_id=(select id from replacement_subscription_capture);
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'expired subscription item denies access');
update core.subscription_items set ends_at=now()+interval '30 days' where subscription_id=(select id from replacement_subscription_capture);
select extensions.lives_ok($$select api.update_subscription_status((select id from replacement_subscription_capture),'past_due')$$,'active subscription can move to past due');
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'past-due subscription denies access immediately');
create temp table second_replacement_capture(id uuid) on commit drop;
insert into second_replacement_capture select api.create_subscription(
 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','90000000-0000-0000-0000-000000000001',now()-interval '1 minute',now()+interval '30 days','USD',
 '[{"plan_entitlement_id":"91000000-0000-0000-0000-000000000001","unit_price_minor":1,"quantity":1}]'::jsonb);
select extensions.ok(private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'replacement is not blocked by a past-due subscription');
update core.plans set status='retired' where id='90000000-0000-0000-0000-000000000001';
select extensions.ok(not private.has_module_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse'),'retired plan cannot authorize module access');
update core.plans set status='active' where id='90000000-0000-0000-0000-000000000001';
insert into iam.platform_permission_grants(user_id,permission_key,granted,updated_by,reason)
select '00000000-0000-0000-0000-000000000007',permission_key,true,'00000000-0000-0000-0000-000000000001','Explicit privileged fixture permission'
from iam.platform_permission_catalog where permission_key<>'company.lifecycle' on conflict do nothing;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000007',true);
select extensions.lives_ok($$select api.update_subscription_status((select id from second_replacement_capture),'canceled')$$,'Subowner can cancel a company subscription through shared platform authority');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
select extensions.throws_ok($$select api.update_subscription_status((select id from second_replacement_capture),'active')$$,'23514',null,'canceled subscription is terminal');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.ok(private.can_access_hse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.dashboard.read','30000000-0000-0000-0000-000000000001',false,null,null),'member can use entitled HSE with functional role and site grant');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment,bill_to_tenant_id,currency,unit_price_minor,quota)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','10000000-0000-0000-0000-000000000001',now()-interval '1 minute',now()+interval '1 day','00000000-0000-0000-0000-000000000001','Synthetic database test grant','tenant_billable','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','USD',123,1);
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','10000000-0000-0000-0000-000000000006',now()-interval '2 days',now()-interval '1 day','00000000-0000-0000-0000-000000000001','Expired synthetic test','complimentary');
select extensions.ok(private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot'),'membership grant enables Copilot for its exact Superadmin beneficiary');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot'),'Superadmin grant does not leak to an employee with the Copilot functional role');
select extensions.ok(not private.has_feature_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','hse.copilot'),'membership grant does not leak across tenants');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000006','hse.copilot'),'expired membership grant is synchronously denied');
update core.entitlement_grants set status='suspended' where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_id='10000000-0000-0000-0000-000000000001' and feature_key='hse.copilot';
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot'),'suspended Copilot grant denies access');
select extensions.lives_ok($$select api.set_entitlement_grant_status((select id from core.entitlement_grants where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_id='10000000-0000-0000-0000-000000000001' and feature_key='hse.copilot'),'suspended','Synthetic suspension')$$,'platform operator can suspend a nonrevoked entitlement grant');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot'),'grant status API suspends access synchronously');
select extensions.lives_ok($$select api.set_entitlement_grant_status((select id from core.entitlement_grants where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_id='10000000-0000-0000-0000-000000000001' and feature_key='hse.copilot'),'active','Synthetic reactivation')$$,'platform operator can restore a suspended grant');
select extensions.throws_ok($$update core.entitlement_grants set quota=9 where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_id='10000000-0000-0000-0000-000000000001' and feature_key='hse.copilot'$$,'23514',null,'issued grant terms cannot be rewritten');
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','10000000-0000-0000-0000-000000000002',now()-interval '1 day',now()+interval '2 days','00000000-0000-0000-0000-000000000001','Synthetic member grant for lifecycle','complimentary');
select api.revoke_entitlement_grant((select id from core.entitlement_grants where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_id='10000000-0000-0000-0000-000000000002' and feature_key='hse.copilot'),'Synthetic feature revoke');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot'),'revoked Copilot grant denies access');
select extensions.throws_ok($$update core.entitlement_grants set revoked_at=null,revoked_by=null,revoke_reason=null where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_id='10000000-0000-0000-0000-000000000002' and feature_key='hse.copilot'$$,'23514',null,'revoked grant cannot be reactivated by rewriting its history');
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','10000000-0000-0000-0000-000000000006',now()+interval '1 day',now()+interval '2 days','00000000-0000-0000-0000-000000000001','Future Copilot grant test','complimentary');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000006','hse.copilot'),'future Copilot grant denies access');
update core.features set enabled=false where feature_key='hse.copilot';
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot'),'globally disabled feature denies Copilot access');
update core.features set enabled=true where feature_key='hse.copilot';
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000005',true);
select extensions.ok(not private.can_access_hse('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse.dashboard.read','30000000-0000-0000-0000-000000000002',false,null,null),'HSE permission cannot bypass a missing company module entitlement');
select extensions.ok(not private.has_hse_permission('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000005','hse.actions.read',null,false,null,null),'tenant-scoped role cannot cross into a different tenant');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse',now()-interval '1 minute',now()+interval '1 day','00000000-0000-0000-0000-000000000001','Synthetic HSE parent for Copilot test','complimentary');
insert into core.entitlement_grants(tenant_id,feature_key,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse.copilot',now()-interval '1 minute',now()+interval '1 day','00000000-0000-0000-0000-000000000001','Synthetic company-level Copilot grant','complimentary');
select extensions.ok(private.has_feature_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','hse.copilot'),'company-level Copilot grant is supported');
select extensions.ok(not api.can_use_feature('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse.copilot','hse.copilot.use',null),'feature grant still requires functional permission');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.is((select count(*)::integer from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000002' and revoked_at is null and (ends_at is null or now()<ends_at)),3,'one membership can hold multiple active functional roles');
select extensions.is((select member_role from iam.memberships where id='10000000-0000-0000-0000-000000000002'),'employee'::text,'functional roles do not change management level');
select extensions.throws_ok($$insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by) select tenant_id,membership_id,role_id,role_version_id,granted_by from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000002' limit 1$$,'23505',null,'duplicate active role assignment is rejected');
select extensions.throws_ok($$insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002',(select id from iam.roles where role_key='foreign_role'),'00000000-0000-0000-0000-000000000001')$$,'23503',null,'cross-tenant role assignment is rejected');
select extensions.ok(exists(select 1 from audit.events where action_key='iam.membership_roles.insert' and jsonb_typeof(summary->'changed_fields')='object' and summary->'changed_fields'<>'{}'::jsonb),'audit event captures safe before/after field details');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.ok(not api.can_use_feature('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','hse.copilot.use',null),'Copilot functional role alone does not bypass the feature entitlement');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000002',true);
select extensions.ok(api.can_use_feature('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','hse.copilot.use',null),'Superadmin uses Copilot only with an explicit membership entitlement');
select extensions.ok((select entitled from api.list_my_entitlements('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') where entitlement_kind='module' and entitlement_key='hse'),'company Superadmin entitlement API reports HSE module access');
select extensions.ok((select entitled from api.list_my_entitlements('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') where entitlement_kind='feature' and entitlement_key='hse.copilot'),'company Superadmin sees its own effective Copilot entitlement');
select extensions.throws_ok($$select * from api.list_my_entitlements('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')$$,'42501',null,'member entitlement API rejects another tenant ID');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.throws_ok($$select * from api.list_my_entitlements('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')$$,'42501',null,'Employee cannot read entitlement administration RPC');
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'usage RPC tests use the actual service_role SQL role');
select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb);
select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb);
reset role;
select extensions.is((select count(*)::integer from core.usage_events where idempotency_key='usage-test-key-0001'),1,'usage retry with same idempotency key creates one event');
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'usage replay and rejection tests use the actual service_role SQL role');
select extensions.is((select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb)),(select id from core.usage_events where idempotency_key='usage-test-key-0001'),'exact usage retry returns original event after exhausting quota');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0001',2,'request','{}'::jsonb)$$,'23505',null,'idempotency key cannot be reused with different usage');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0001',1,'minute','{}'::jsonb)$$,'23505',null,'idempotency key compares usage unit');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.inspections.read','usage-test-key-0001',1,'request','{}'::jsonb)$$,'23505',null,'idempotency key compares feature');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0001',1,'request','{"workflow":"different"}'::jsonb)$$,'23505',null,'idempotency key compares safe metadata');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb)$$,'23505',null,'idempotency key compares beneficiary membership');
select extensions.throws_ok($$select api.record_feature_usage('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb)$$,'23505',null,'idempotency key cannot be reused for another tenant');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0002',1,'minute','{}'::jsonb)$$,'22023',null,'new usage rejects a unit that does not match the feature');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000001','hse.copilot','usage-test-key-0002',1,'request','{"prompt":"not allowed"}'::jsonb)$$,'42501',null,'usage ledger rejects prompt content');
select extensions.ok(has_function_privilege('service_role','api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb)','EXECUTE') and has_function_privilege('service_role','api.invoice_usage_event(uuid,uuid,text)','EXECUTE'),'trusted service role has the only usage and invoice RPC execution path');
reset role;
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'invitation RPC tests use the actual service_role SQL role');
create temp table invitation_capture(invitation_id uuid,token text) on commit drop;
insert into invitation_capture select invitation_id,token from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','other@example.test','company_admin','00000000-0000-0000-0000-000000000002',interval '7 days');
select extensions.is((select octet_length(token_hash)::integer from iam.invitations where id=(select invitation_id from invitation_capture)),32,'invitation persists only a 32-byte hash');
select extensions.ok(not exists(select 1 from information_schema.columns where table_schema='iam' and table_name='invitations' and column_name='token'),'invitation schema has no raw-token column');
select extensions.ok(not has_function_privilege('authenticated','api.create_invitation(uuid,text,text,uuid,interval)','EXECUTE'),'browser authenticated role cannot receive raw invitation tokens');
select extensions.throws_ok($$select api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','forbidden@example.test','company_superadmin','00000000-0000-0000-0000-000000000002',interval '7 days')$$,'42501',null,'invitation cannot create another Company Superadmin');
select extensions.throws_ok($$select api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','forbidden@example.test','platform_operator','00000000-0000-0000-0000-000000000002',interval '7 days')$$,'42501',null,'invitation cannot create a platform operator');
select extensions.throws_ok($$select api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','forbidden@example.test','employee','00000000-0000-0000-0000-000000000004',interval '7 days')$$,'42501',null,'service caller cannot impersonate a Superadmin from another tenant');
create temp table expired_invitation_capture(invitation_id uuid,token text) on commit drop;
insert into expired_invitation_capture select invitation_id,token from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','expired-invite@example.test','employee','00000000-0000-0000-0000-000000000002',interval '7 days');
reset role;
update iam.invitations set created_at=now()-interval '2 days',expires_at=now()-interval '1 day' where id=(select invitation_id from expired_invitation_capture);
set local role service_role;
select extensions.throws_ok($$select api.accept_invitation((select token from expired_invitation_capture),'00000000-0000-0000-0000-000000000009')$$,'22023',null,'expired invitation is denied');
create temp table reinvite_capture(invitation_id uuid,token text) on commit drop;
insert into reinvite_capture select invitation_id,token from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','reinvite@example.test','employee','00000000-0000-0000-0000-000000000002',interval '7 days');
reset role;
update iam.invitations set created_at=now()-interval '2 days',expires_at=now()-interval '1 day' where id=(select invitation_id from reinvite_capture);
set local role service_role;
select extensions.lives_ok($$select * from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','reinvite@example.test','employee','00000000-0000-0000-0000-000000000002',interval '7 days')$$,'expired pending invite is closed atomically so same email can be reinvited');
create temp table revoked_invitation_capture(invitation_id uuid,token text) on commit drop;
insert into revoked_invitation_capture select invitation_id,token from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','revoked@example.test','employee','00000000-0000-0000-0000-000000000002',interval '7 days');
reset role;
update iam.invitations set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000002',revoke_reason='Synthetic test revoke' where id=(select invitation_id from revoked_invitation_capture);
set local role service_role;
select extensions.throws_ok($$select api.accept_invitation((select token from revoked_invitation_capture),'00000000-0000-0000-0000-000000000003')$$,'22023',null,'revoked invitation is denied');
create temp table tenant_b_invitation_capture(invitation_id uuid,token text) on commit drop;
insert into tenant_b_invitation_capture select invitation_id,token from api.create_invitation('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','tenant-b-invite@example.test','employee','00000000-0000-0000-0000-000000000004',interval '7 days');
reset role;
grant select on tenant_b_invitation_capture to authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000002',true);
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select extensions.throws_ok($$select api.revoke_invitation((select invitation_id from tenant_b_invitation_capture),'Cross tenant attempt')$$,'22023',null,'Company Superadmin cannot revoke another tenant invitation');
reset role;
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select extensions.ok(not has_function_privilege('authenticated','api.accept_invitation(text,uuid)','EXECUTE'),'browser cannot invoke raw-token acceptance RPC');
reset role;
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'acceptance RPC tests use the actual service_role SQL role');
select extensions.throws_ok($$select api.accept_invitation((select token from invitation_capture),'00000000-0000-0000-0000-000000000008')$$,'42501',null,'unverified Auth email cannot accept invitation');
select extensions.throws_ok($$select api.accept_invitation((select token from invitation_capture),'00000000-0000-0000-0000-000000000003')$$,'22023',null,'verified but wrong email cannot accept invitation');
select extensions.lives_ok($$select api.accept_invitation((select token from invitation_capture),'00000000-0000-0000-0000-000000000005')$$,'verified matching Auth email accepts invitation');
select extensions.is((select member_role from iam.memberships where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and user_id='00000000-0000-0000-0000-000000000005'),'company_admin'::text,'invitation provisions only the intended management level');
select extensions.throws_ok($$select api.accept_invitation((select token from invitation_capture),'00000000-0000-0000-0000-000000000005')$$,'22023',null,'accepted invitation token cannot be replayed');
reset role;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000005',true);
set local role authenticated;
select extensions.is((select count(*)::integer from core.plans),0,'Company Admin cannot read plan catalog');
select extensions.is((select count(*)::integer from core.invoices),0,'Company Admin cannot read invoices');
select extensions.is((select count(*)::integer from core.plan_entitlements),0,'Company Admin cannot read plan entitlement rates');
select extensions.is((select count(*)::integer from core.subscriptions),0,'Company Admin cannot read subscription snapshots');
select extensions.is((select count(*)::integer from core.usage_events),0,'Company Admin cannot read usage billing events');
select extensions.is((select count(*)::integer from core.invoice_items),0,'Company Admin cannot read invoice lines');
select extensions.is((select count(*)::integer from core.payments),0,'Company Admin cannot read payments');
with changed as (update iam.membership_roles set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000005',revoke_reason='Privilege test' where membership_id='10000000-0000-0000-0000-000000000002' returning id) select extensions.is((select count(*)::integer from changed),0,'Company Admin cannot grant or revoke functional roles');
select extensions.throws_ok($$insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000005')$$,'42501',null,'Company Admin cannot grant a site scope');
select extensions.throws_ok($$insert into iam.memberships(tenant_id,user_id,member_role,status,email) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000008','employee','active','unverified@example.test')$$,'42501',null,'Company Admin cannot directly insert a membership');
select extensions.throws_ok($$update iam.memberships set status='suspended' where id='10000000-0000-0000-0000-000000000003'$$,'42501',null,'Company Admin cannot directly suspend a membership');
select extensions.throws_ok($$update iam.memberships set member_role='company_superadmin' where id='10000000-0000-0000-0000-000000000002'$$,'42501',null,'Company Admin cannot change another membership management level');
select extensions.ok(not has_function_privilege('authenticated','api.set_membership_status(uuid,uuid,text,uuid,text)','EXECUTE'),'Company Admin cannot invoke trusted membership lifecycle RPC');
select extensions.throws_ok($$select api.set_membership_status('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','suspended','00000000-0000-0000-0000-000000000005','Unauthorized admin attempt')$$,'42501',null,'Company Admin cannot suspend a membership');
select extensions.ok(not has_function_privilege('authenticated','api.create_invitation(uuid,text,text,uuid,interval)','EXECUTE'),'Company Admin cannot invoke invitation creation');
select extensions.throws_ok($$select api.issue_entitlement_grant('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',null,'hse.copilot',null,now(),now()+interval '1 day','Denied company grant','complimentary',null,null,null)$$,'42501',null,'Company Admin cannot issue commercial entitlements');
reset role;
select set_config('request.jwt.claim.role','service_role',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'invoice RPC tests use the actual service_role SQL role');
select api.create_invoice_draft('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','TEST-INV-1','USD',now()-interval '1 day',now()+interval '1 day');
select extensions.lives_ok($$select api.invoice_usage_event((select id from core.usage_events where idempotency_key='usage-test-key-0001'),(select id from core.invoices where invoice_number='TEST-INV-1'),'Synthetic test usage')$$,'one usage event can be invoiced');
select extensions.is((select api.invoice_usage_event((select id from core.usage_events where idempotency_key='usage-test-key-0001'),(select id from core.invoices where invoice_number='TEST-INV-1'),'Synthetic test usage')),(select id from core.invoice_items where usage_event_id=(select id from core.usage_events where idempotency_key='usage-test-key-0001')),'invoice retry returns the original line id');
select extensions.is((select count(*)::integer from core.invoice_items where usage_event_id=(select id from core.usage_events where idempotency_key='usage-test-key-0001')),1,'usage event is invoiced at most once');
select extensions.is((select total_minor from core.invoices where invoice_number='TEST-INV-1'),123::bigint,'invoice uses exact minor-unit rate snapshot');
select extensions.throws_ok($$update core.usage_events set quantity=2 where idempotency_key='usage-test-key-0001'$$,'42501',null,'usage event ledger rejects mutation');
select extensions.throws_ok($$delete from core.usage_events where idempotency_key='usage-test-key-0001'$$,'42501',null,'usage event ledger rejects hard delete');
select extensions.throws_ok($$update core.invoice_items set amount_minor=1 where usage_event_id=(select id from core.usage_events where idempotency_key='usage-test-key-0001')$$,'42501',null,'invoice line ledger rejects mutation');
select api.create_invoice_draft('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','TEST-INV-2','USD',now()-interval '1 day',now()+interval '1 day');
select extensions.throws_ok($$select api.invoice_usage_event((select id from core.usage_events where idempotency_key='usage-test-key-0001'),(select id from core.invoices where invoice_number='TEST-INV-2'),'Conflicting invoice')$$,'23505',null,'usage event cannot be invoiced twice to different invoices');
select extensions.ok(not has_table_privilege('authenticated','core.usage_events','DELETE') and not has_table_privilege('authenticated','core.invoice_items','DELETE') and not has_table_privilege('authenticated','core.payments','DELETE'),'usage, invoice, and payment ledgers cannot be hard-deleted by users');
reset role;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.is((select count(*)::integer from core.tenants),1,'Company Superadmin is confined to its own tenant');
select extensions.throws_ok($$insert into iam.memberships(tenant_id,user_id,member_role,status,email) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000008','employee','active','unverified@example.test')$$,'42501',null,'Company Superadmin cannot insert an active membership directly');
select extensions.throws_ok($$update iam.memberships set status='active' where id='10000000-0000-0000-0000-000000000009'$$,'42501',null,'Company Superadmin cannot activate an invited membership directly');
select extensions.throws_ok($$update iam.memberships set status='active' where id='10000000-0000-0000-0000-000000000010'$$,'42501',null,'Company Superadmin cannot reactivate a suspended membership directly');
select extensions.throws_ok($$update iam.memberships set member_role='company_superadmin' where id='10000000-0000-0000-0000-000000000003'$$,'42501',null,'Company Superadmin cannot directly change a member management level');
select extensions.throws_ok($$update iam.memberships set user_id='00000000-0000-0000-0000-000000000008' where id='10000000-0000-0000-0000-000000000003'$$,'42501',null,'Company Superadmin cannot directly reassign a member identity');
select extensions.throws_ok($$update iam.memberships set tenant_id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' where id='10000000-0000-0000-0000-000000000003'$$,'42501',null,'Company Superadmin cannot directly move a membership across tenants');
select extensions.throws_ok($$update iam.memberships set email='forged@example.test' where id='10000000-0000-0000-0000-000000000003'$$,'42501',null,'Company Superadmin cannot directly change a verified membership email');
select extensions.throws_ok($$update iam.memberships set display_name='Synthetic profile edit' where id='10000000-0000-0000-0000-000000000003'$$,'42501',null,'No direct membership profile-column write is granted');
select extensions.throws_ok($$update iam.memberships set email='cross-tenant@example.test' where id='10000000-0000-0000-0000-000000000007'$$,'42501',null,'Company Superadmin cannot manipulate a cross-tenant membership');
select extensions.ok(not has_function_privilege('authenticated','api.set_membership_status(uuid,uuid,text,uuid,text)','EXECUTE'),'Company Superadmin cannot call the trusted membership lifecycle RPC directly');
select extensions.is((select count(*)::integer from core.features),0,'company Superadmin cannot read internal feature catalog');
select extensions.is((select count(*)::integer from core.plans),0,'company Superadmin cannot read plan prices');
select extensions.is((select count(*)::integer from core.plan_entitlements),0,'company Superadmin cannot read plan rates or quota');
select extensions.is((select count(*)::integer from core.subscriptions),0,'company Superadmin cannot read subscription snapshots');
select extensions.is((select count(*)::integer from core.usage_events),0,'company Superadmin cannot read usage rates or events');
select extensions.is((select count(*)::integer from core.invoices),0,'company Superadmin cannot read invoices');
select extensions.is((select count(*)::integer from core.invoice_items),0,'company Superadmin cannot read invoice items');
select extensions.is((select count(*)::integer from core.payments),0,'company Superadmin cannot read payments');
select extensions.ok(has_table_privilege('authenticated','core.plans','SELECT'),'table SELECT grant alone is still constrained by platform-only RLS');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is((select count(*)::integer from core.tenants),1,'Employee is confined to its own tenant');
select extensions.is((select count(*)::integer from core.plans),0,'Employee cannot read internal commercial catalog');
select extensions.is((select count(*)::integer from core.usage_events),0,'Employee cannot read usage records');
select extensions.is((select count(*)::integer from core.invoices),0,'Employee cannot read invoices');
select extensions.is((select count(*)::integer from core.payments),0,'Employee cannot read payments');
select extensions.throws_ok($$insert into iam.memberships(tenant_id,user_id,member_role,status,email) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000008','employee','active','unverified@example.test')$$,'42501',null,'Employee cannot provision another membership');
select extensions.throws_ok($$insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000003')$$,'42501',null,'Employee cannot expand its own site scope');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000002',true);
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by)
 values('40000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','{"en":"Test","ar":"اختبار"}','test','published',1,'{}','10000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by)
 values('50000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','40000000-0000-0000-0000-000000000001',1,'{}','00000000-0000-0000-0000-000000000001');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id,status,current_stage,submitted_at)
 values('60000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','30000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','Approval test','10000000-0000-0000-0000-000000000002','submitted','reviewer_1',now()),
 ('60000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','30000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','Return test','10000000-0000-0000-0000-000000000002','submitted','reviewer_1',now());
insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','inspection','60000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
select extensions.throws_ok($$insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by) values('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','inspection','60000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$$,'23503',null,'task assignment cannot reference another tenant task');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000008','30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
insert into iam.org_unit_access(tenant_id,membership_id,org_unit_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000008','20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
insert into iam.member_permissions(tenant_id,membership_id,permission_key,scope_kind,site_id,can_read,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000008','hse.findings.read','site','30000000-0000-0000-0000-000000000001',true,'00000000-0000-0000-0000-000000000001');
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
 select r.tenant_id,'10000000-0000-0000-0000-000000000008',r.id,rv.id,'00000000-0000-0000-0000-000000000001'
 from iam.roles r join iam.role_versions rv on rv.tenant_id=r.tenant_id and rv.role_id=r.id and rv.version_no=1
 where r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and r.role_key in ('site_reader','org_reader','task_reader');
insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by)
 select mr.tenant_id,mr.id,'30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001' from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where mr.membership_id='10000000-0000-0000-0000-000000000008' and r.role_key='site_reader';
insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by)
 select mr.tenant_id,mr.id,'20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001' from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where mr.membership_id='10000000-0000-0000-0000-000000000008' and r.role_key='org_reader';
insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000008','inspection','60000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000011',true);
select extensions.ok(private.can_access_hse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.findings.read','30000000-0000-0000-0000-000000000001',false,null,null),'reactivation fixture initially has direct HSE access');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000008','hse.inspections.read','30000000-0000-0000-0000-000000000001',false,'inspection','60000000-0000-0000-0000-000000000001'),'reactivation fixture initially has task-scoped access');
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'membership suspension uses the actual service_role SQL role');
select api.set_membership_status('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000008','suspended','00000000-0000-0000-0000-000000000002','Verified re-invitation required');
reset role;
select extensions.ok(not private.can_access_hse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.findings.read','30000000-0000-0000-0000-000000000001',false,null,null),'suspended membership immediately loses HSE access');
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
create temp table reactivation_invitation_capture(invitation_id uuid,token text) on commit drop;
insert into reactivation_invitation_capture select invitation_id,token from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','reactivate@example.test','employee','00000000-0000-0000-0000-000000000002',interval '7 days');
select extensions.lives_ok($$select api.accept_invitation((select token from reactivation_invitation_capture),'00000000-0000-0000-0000-000000000011')$$,'verified invite reactivates suspended membership');
reset role;
select set_config('request.jwt.claim.role','authenticated',true);
select extensions.is((select count(*)::integer from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000008' and revoked_at is null),0,'reactivation revokes all prior functional roles');
select extensions.is((select count(*)::integer from iam.membership_role_sites where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_role_id in (select id from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000008') and revoked_at is null),0,'reactivation revokes prior role site bindings');
select extensions.is((select count(*)::integer from iam.membership_role_org_units where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and membership_role_id in (select id from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000008') and revoked_at is null),0,'reactivation revokes prior role organization bindings');
select extensions.is((select count(*)::integer from iam.member_permissions where membership_id='10000000-0000-0000-0000-000000000008' and active),0,'reactivation disables prior direct permissions');
select extensions.is((select count(*)::integer from iam.site_access where membership_id='10000000-0000-0000-0000-000000000008' and active),0,'reactivation disables prior site access');
select extensions.is((select count(*)::integer from iam.org_unit_access where membership_id='10000000-0000-0000-0000-000000000008' and active),0,'reactivation disables prior organization access');
select extensions.is((select count(*)::integer from iam.task_assignments where membership_id='10000000-0000-0000-0000-000000000008' and active),0,'reactivation disables prior task assignments');
select set_config('request.jwt.claim.role','authenticated',true);
select extensions.ok(not private.can_access_hse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.findings.read','30000000-0000-0000-0000-000000000001',false,null,null),'reactivated membership cannot reuse old HSE access');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,'inspection','60000000-0000-0000-0000-000000000001'),'task assignment does not bypass missing site access');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.findings.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'site-scoped role requires independent member site access');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.findings.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'site-scoped role works at its bound site');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.actions.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'tenant-scoped role grants its permission within the tenant');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,'inspection','60000000-0000-0000-0000-000000000001'),'site access alone does not replace required org-unit access for assigned task');
insert into iam.org_unit_access(tenant_id,membership_id,org_unit_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001');
insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by,granted_at,ends_at)
 select mr.tenant_id,mr.id,'30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001',now()-interval '2 days',now()-interval '1 day'
 from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='site_reader';
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.findings.read','30000000-0000-0000-0000-000000000003'::uuid,false,null,null),'expired membership role site binding denies access synchronously');
insert into iam.org_unit_access(tenant_id,membership_id,org_unit_id,granted_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','20000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001');
insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by,granted_at,ends_at)
 select mr.tenant_id,mr.id,'20000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001',now()-interval '2 days',now()-interval '1 day'
 from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='org_reader';
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000003'::uuid,false,null,null),'expired membership role organization binding denies access synchronously');
select extensions.throws_ok($$insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by) select mr.tenant_id,mr.id,'20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001' from iam.membership_roles mr join iam.roles r on r.id=mr.role_id where mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='site_reader'$$,'23514',null,'site-only role cannot be bound to an organization unit');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'org-unit grant allows its exact unit');
update iam.membership_role_org_units ro set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000001',revoke_reason='Synthetic org scope revoke'
 from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where ro.membership_role_id=mr.id and ro.org_unit_id='20000000-0000-0000-0000-000000000001'
   and mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='org_reader';
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'revoked organization scope binding denies access synchronously');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000003'::uuid,false,null,null),'site grant does not override a different org-unit scope');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.findings.read','30000000-0000-0000-0000-000000000003'::uuid,false,null,null),'site-scoped role does not grant an unbound site');
update iam.membership_role_sites rs set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000001',revoke_reason='Synthetic scope revoke'
 from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
 where rs.membership_role_id=mr.id and rs.site_id='30000000-0000-0000-0000-000000000001'
   and mr.membership_id='10000000-0000-0000-0000-000000000005' and r.role_key='site_reader';
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.findings.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'revoked membership role site binding denies access synchronously');
select extensions.throws_ok($$update iam.membership_role_sites set granted_at=now() where site_id='30000000-0000-0000-0000-000000000001' and revoked_at is not null$$,'23514',null,'revoked scope binding history cannot be rewritten');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.actions.read','30000000-0000-0000-0000-000000000003'::uuid,false,null,null),'tenant-scoped role spans authorized sites only inside the tenant');
update iam.membership_roles mr set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000001',revoke_reason='Synthetic role revoke'
 from iam.roles r where r.id=mr.role_id and r.role_key='site_reader' and mr.membership_id='10000000-0000-0000-0000-000000000005';
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.findings.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'revoked role assignment immediately stops granting access');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000003'::uuid,false,'inspection','60000000-0000-0000-0000-000000000001'),'task assignment cannot grant access at a different site');
select extensions.throws_ok($$insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by,site_id) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','inspection','60000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','30000000-0000-0000-0000-000000000003')$$,'23503',null,'task assignment cannot be rebound to a different site');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,'inspection','60000000-0000-0000-0000-000000000001'),'task assignment works only after matching site and org-unit access');
update iam.membership_roles mr set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000001',revoke_reason='Isolate task-scope test'
 from iam.roles r where r.id=mr.role_id and r.role_key='org_reader' and mr.membership_id='10000000-0000-0000-0000-000000000005';
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,'inspection','60000000-0000-0000-0000-000000000002'),'task role does not grant unassigned task');
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003',id,'00000000-0000-0000-0000-000000000001' from iam.roles where role_key='reviewer_1' and tenant_id is null;
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005',id,'00000000-0000-0000-0000-000000000001' from iam.roles where role_key='reviewer_2' and tenant_id is null;
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005',id,'00000000-0000-0000-0000-000000000001' from iam.roles where role_key='final_reviewer' and tenant_id is null;
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','hse.inspections.create','30000000-0000-0000-0000-000000000001',true,null,null),'expired role assignment immediately stops granting access');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000004',true);
set local role authenticated;
select extensions.lives_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000001','reviewer_1','approved','10000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004',1)$$,'first reviewer approval advances to reviewer 2');
select extensions.is((select current_stage from hse.inspections where id='60000000-0000-0000-0000-000000000001'),'reviewer_2'::text,'review approval updates workflow stage');
select extensions.lives_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,reason,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000002','reviewer_1','returned','10000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004','Synthetic return reason',1)$$,'first reviewer can return an initially submitted inspection');
select extensions.is((select status from hse.inspections where id='60000000-0000-0000-0000-000000000002'),'returned'::text,'review return is applied');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.throws_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000001','reviewer_2','approved','10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',1)$$,'40001',null,'stale review revision is rejected');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000006',true);
set local role authenticated;
select extensions.throws_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000002','reviewer_2','approved','10000000-0000-0000-0000-000000000005','00000000-0000-0000-0000-000000000006',1)$$,'42501',null,'Reviewer 2 cannot review a Reviewer 1 stage');
select extensions.lives_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000001','reviewer_2','approved','10000000-0000-0000-0000-000000000005','00000000-0000-0000-0000-000000000006',2)$$,'Reviewer 2 approval advances to Final Reviewer');
select extensions.is((select current_stage from hse.inspections where id='60000000-0000-0000-0000-000000000001'),'final_reviewer'::text,'Reviewer 2 approval changes stage');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000006',true);
set local role authenticated;
select extensions.lives_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000001','final_reviewer','approved','10000000-0000-0000-0000-000000000005','00000000-0000-0000-0000-000000000006',3)$$,'Final Reviewer approval completes the workflow');
select extensions.is((select status from hse.inspections where id='60000000-0000-0000-0000-000000000001'),'approved'::text,'final approval marks inspection approved');
reset role;
select extensions.is((select reason from hse.inspection_reviews where inspection_id='60000000-0000-0000-0000-000000000002' and decision='returned'),'Synthetic return reason'::text,'review return reason is retained');
select extensions.is((select actor_user_id from hse.inspection_reviews where inspection_id='60000000-0000-0000-0000-000000000002' and decision='returned'),'00000000-0000-0000-0000-000000000004'::uuid,'review actor is retained');
select extensions.ok(not has_table_privilege('authenticated','hse.inspection_reviews','DELETE'),'review history has no authenticated DELETE privilege');
select extensions.ok(not has_table_privilege('authenticated','hse.inspection_reviews','UPDATE'),'review history has no authenticated UPDATE privilege');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is((select count(*)::integer from core.tenants),1,'tenant RLS limits employee to own company');
with changed as (update iam.membership_roles set revoked_at=now() where membership_id='10000000-0000-0000-0000-000000000002' returning id) select extensions.is((select count(*)::integer from changed),0,'employee cannot change role assignments');
reset role;
select set_config('request.jwt.claim.role','anon',true);
select extensions.ok(not has_table_privilege('anon','core.plans','SELECT') and not has_table_privilege('anon','core.invoices','SELECT') and not has_table_privilege('anon','core.payments','SELECT'),'anon has no commercial-data table privileges');
select extensions.ok(not has_function_privilege('anon','api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb)','EXECUTE') and not has_function_privilege('anon','api.accept_invitation(text,uuid)','EXECUTE'),'anon cannot invoke trusted billing or invitation RPCs');
set local role anon;
select extensions.is(current_user::text,'anon'::text,'anonymous access checks use the actual anon SQL role');
select extensions.throws_ok($$insert into iam.memberships(tenant_id,user_id,member_role,status,email) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000008','employee','active','unverified@example.test')$$,'42501',null,'anon cannot insert a membership');
select extensions.throws_ok($$update iam.memberships set status='active' where id='10000000-0000-0000-0000-000000000009'$$,'42501',null,'anon cannot activate an invited membership');
reset role;
select set_config('request.jwt.claim.role','authenticated',true);
select extensions.ok(not has_table_privilege('authenticated','hse.follow_ups','DELETE'),'authenticated has no hard-delete privilege');
select extensions.ok(not has_table_privilege('authenticated','iam.memberships','DELETE') and not has_table_privilege('authenticated','iam.member_permissions','DELETE') and not has_table_privilege('authenticated','core.entitlement_grants','DELETE') and not has_table_privilege('authenticated','core.usage_events','DELETE') and not has_table_privilege('authenticated','core.invoice_items','DELETE') and not has_table_privilege('authenticated','core.payments','DELETE'),'business history tables have no authenticated DELETE grants');
select extensions.throws_ok($$delete from audit.events where id=(select max(id) from audit.events)$$,'42501',null,'audit ledger rejects hard delete');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000007',true);
set local role authenticated;
select extensions.is(jsonb_array_length(api.platform_list_companies()->'rows'),2,'Subowner has audited platform-wide tenant access');
select extensions.is((select count(*)::integer from core.plans),2,'Subowner can see commercial catalog');
select extensions.is(jsonb_array_length(api.platform_read_company('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','core.invoice_items')->'rows'),1,'Subowner can inspect company invoice items through audited RPC');
select extensions.ok(not has_table_privilege('authenticated','iam.platform_operators','UPDATE'),'Subowner has no direct operator roster write privilege');
create temp table subowner_grant_capture(id uuid) on commit drop;
insert into subowner_grant_capture select api.issue_entitlement_grant('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse',null,null,now(),now()+interval '1 day','Synthetic Subowner authority test','platform_absorbed',null,null,null);
select extensions.ok(exists(select 1 from jsonb_array_elements(api.platform_read_company('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','core.entitlement_grants')->'rows') row where (row->>'id')::uuid=(select id from subowner_grant_capture) and row->>'granted_by'='00000000-0000-0000-0000-000000000007'),'Subowner can issue a cross-company grant like the Owner');
select extensions.lives_ok($$select api.revoke_entitlement_grant((select id from subowner_grant_capture),'Synthetic Subowner revoke')$$,'Subowner can revoke a cross-company grant');
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000007',false)$$,'42501',null,'Subowner cannot deactivate itself or manage operator roster');
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',true)$$,'42501',null,'Subowner cannot create or reactivate another Subowner');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select extensions.is(jsonb_array_length(api.platform_list_companies()->'rows'),2,'Owner can access all companies through audited RPC');
select extensions.is(jsonb_array_length(api.platform_read_company('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','core.invoice_items')->'rows'),1,'Owner can inspect company invoice lines through audited RPC');
create temp table created_tenant_capture(tenant_id uuid) on commit drop;
insert into created_tenant_capture select api.create_tenant('Synthetic No Entitlement Tenant','test','00000000-0000-0000-0000-000000000010');
reset role;
select extensions.ok(not private.has_module_entitlement((select tenant_id from created_tenant_capture),'hse'),'new tenant receives no HSE module without a subscription or grant');
select extensions.ok(not exists(select 1 from core.tenant_entitlements where tenant_id=(select tenant_id from created_tenant_capture)),'new tenant creation does not seed a legacy HSE entitlement');
set local role authenticated;
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000001',false)$$,'42501',null,'Owner management RPC cannot deactivate the Owner');
select extensions.lives_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',true)$$,'Owner can create a Subowner');
reset role;
select extensions.ok(exists(select 1 from iam.platform_operators where user_id='00000000-0000-0000-0000-000000000008' and operator_role='subowner' and active),'Owner-created Subowner is active');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000007',true);
set local role authenticated;
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',false)$$,'42501',null,'Subowner cannot deactivate another Subowner');
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',true)$$,'42501',null,'Subowner cannot reactivate another Subowner');
reset role;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
set local role authenticated;
select extensions.lives_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',false)$$,'Owner can deactivate a Subowner');
reset role;
select extensions.ok(exists(select 1 from iam.platform_operators where user_id='00000000-0000-0000-0000-000000000008' and operator_role='subowner' and not active),'Owner-deactivated Subowner is inactive');
set local role authenticated;
select extensions.lives_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',true)$$,'Owner can reactivate a Subowner');
reset role;
select extensions.ok(exists(select 1 from iam.platform_operators where user_id='00000000-0000-0000-0000-000000000008' and operator_role='subowner' and active),'Owner-reactivated Subowner is active');
set local role authenticated;
select extensions.lives_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000008',false)$$,'Owner can deactivate a reactivated Subowner');
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000010',true)$$,'23514',null,'Owner cannot make a company member a Subowner');
reset role;
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select extensions.is(current_user::text,'service_role'::text,'membership lifecycle authorization tests use the actual service_role SQL role');
select extensions.throws_ok($$select api.set_membership_status('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000011','active','00000000-0000-0000-0000-000000000004','Attempt activation')$$,'42501',null,'trusted status RPC does not expose activation');
select extensions.throws_ok($$select api.set_membership_status('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','suspended','00000000-0000-0000-0000-000000000002','Cross tenant attempt')$$,'42501',null,'Company Superadmin cannot use lifecycle RPC against another tenant');
select extensions.throws_ok($$select api.set_membership_status('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','suspended','00000000-0000-0000-0000-000000000005','Admin actor attempt')$$,'42501',null,'Company Admin is not authorized as a membership lifecycle actor');
select extensions.throws_ok($$select api.set_membership_status('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000007','suspended','00000000-0000-0000-0000-000000000004','Self suspension attempt')$$,'42501',null,'Company Superadmin cannot suspend itself through the lifecycle RPC');
select extensions.throws_ok($$select api.set_membership_status('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000006','ended','00000000-0000-0000-0000-000000000002','Peer promotion-level attempt')$$,'42501',null,'Company Superadmin cannot end another suspended Company Superadmin');
select extensions.lives_ok($$select api.set_membership_status('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000011','suspended','00000000-0000-0000-0000-000000000004','Synthetic service lifecycle test')$$,'Company Superadmin can suspend an employee through trusted lifecycle RPC');
reset role;
select extensions.is((select status from iam.memberships where id='10000000-0000-0000-0000-000000000011'),'suspended'::text,'trusted lifecycle RPC applies the requested suspension');
set local role service_role;
select extensions.throws_ok($$select api.set_membership_status('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000011','active','00000000-0000-0000-0000-000000000004','Attempt reactivation')$$,'42501',null,'trusted status RPC cannot reactivate an actually suspended membership');
select extensions.lives_ok($$select api.set_membership_status('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000011','ended','00000000-0000-0000-0000-000000000004','Synthetic lifecycle end')$$,'Company Superadmin can end a suspended membership through trusted lifecycle RPC');
reset role;
select extensions.is((select status from iam.memberships where id='10000000-0000-0000-0000-000000000011'),'ended'::text,'trusted lifecycle RPC applies the ended status');
select extensions.ok(exists(select 1 from audit.events where action_key='iam.membership.status_changed' and record_id='10000000-0000-0000-0000-000000000011' and summary->>'after_status'='ended'),'membership lifecycle changes emit an audit event');
select * from extensions.finish();
rollback;
