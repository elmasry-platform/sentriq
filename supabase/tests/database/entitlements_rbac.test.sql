create extension if not exists pgtap with schema extensions;
grant usage on schema extensions to authenticated;
grant usage on schema extensions to service_role;
grant execute on all functions in schema extensions to authenticated;
grant execute on all functions in schema extensions to service_role;
begin;
select extensions.plan(42);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000001','authenticated','authenticated','owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000002','authenticated','authenticated','admin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000003','authenticated','authenticated','employee@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000004','authenticated','authenticated','reviewer@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000005','authenticated','authenticated','other@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000006','authenticated','authenticated','task@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000007','authenticated','authenticated','subowner@example.test','',now(),'{}','{}',now(),now());
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
 ('10000000-0000-0000-0000-000000000005','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','00000000-0000-0000-0000-000000000006','employee','active','task@example.test');
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
insert into iam.roles(tenant_id,role_key,label,created_by) values
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','copilot_user','Copilot User','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','task_reader','Task Reader','00000000-0000-0000-0000-000000000001'),
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','org_reader','Org Unit Reader','00000000-0000-0000-0000-000000000001'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','foreign_role','Foreign Role','00000000-0000-0000-0000-000000000001');
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
select r.id,p.permission_key,p.scope_kind,p.can_read,p.can_write from iam.roles r join (values
 ('copilot_user','hse.copilot.use','tenant',true,false),
 ('task_reader','hse.inspections.read','assigned_task',true,false)) p(role_key,permission_key,scope_kind,can_read,can_write)
 on r.role_key=p.role_key and r.tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
select id,'hse.inspections.read','org_unit',true,false from iam.roles where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and role_key='org_reader';
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002',id,'00000000-0000-0000-0000-000000000001'
 from iam.roles where role_key in ('inspector','auditor') and tenant_id is null;
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002',id,'00000000-0000-0000-0000-000000000001'
 from iam.roles where role_key='copilot_user' and tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005',id,'00000000-0000-0000-0000-000000000001'
 from iam.roles where role_key in ('task_reader','org_reader') and tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004',id,'00000000-0000-0000-0000-000000000001'
 from iam.roles where role_key='auditor' and tenant_id is null;
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by,starts_at,ends_at)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003',id,'00000000-0000-0000-0000-000000000001',now()-interval '2 days',now()-interval '1 day'
 from iam.roles where role_key='inspector' and tenant_id is null;

select extensions.ok(private.has_module_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse'),'legacy HSE entitlement still enables HSE');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot'),'HSE does not implicitly license Copilot');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.ok(private.can_access_hse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.dashboard.read','30000000-0000-0000-0000-000000000001',false,null,null),'member can use entitled HSE with functional role and site grant');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment,bill_to_tenant_id,currency,unit_price_minor,quota)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','10000000-0000-0000-0000-000000000002',now()-interval '1 minute',now()+interval '1 day','00000000-0000-0000-0000-000000000001','Synthetic database test grant','tenant_billable','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','USD',123,100);
insert into core.entitlement_grants(tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','10000000-0000-0000-0000-000000000003',now()-interval '2 days',now()-interval '1 day','00000000-0000-0000-0000-000000000001','Expired synthetic test','complimentary');
select extensions.ok(private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot'),'membership grant enables Copilot for its exact beneficiary');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','hse.copilot'),'membership grant does not leak to another member');
select extensions.ok(not private.has_feature_entitlement('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','10000000-0000-0000-0000-000000000004','hse.copilot'),'membership grant does not leak across tenants');
select extensions.ok(not private.has_feature_entitlement('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','hse.copilot'),'expired membership grant is synchronously denied');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000005',true);
select extensions.ok(not private.can_access_hse('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','hse.dashboard.read','30000000-0000-0000-0000-000000000002',false,null,null),'HSE permission cannot bypass a missing company module entitlement');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.is((select count(*)::integer from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000002' and revoked_at is null and (ends_at is null or now()<ends_at)),3,'one membership can hold multiple active functional roles');
select extensions.is((select member_role from iam.memberships where id='10000000-0000-0000-0000-000000000002'),'employee'::text,'functional roles do not change management level');
select extensions.throws_ok($$insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by) select tenant_id,membership_id,role_id,granted_by from iam.membership_roles where membership_id='10000000-0000-0000-0000-000000000002' limit 1$$,'23505','duplicate active role assignment is rejected');
select extensions.throws_ok($$insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002',(select id from iam.roles where role_key='foreign_role'),'00000000-0000-0000-0000-000000000001')$$,'23503','cross-tenant role assignment is rejected');
select extensions.ok(exists(select 1 from audit.events where action_key='iam.membership_roles.insert' and jsonb_typeof(summary->'changed_fields')='object' and summary->'changed_fields'<>'{}'::jsonb),'audit event captures safe before/after field details');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
select extensions.ok(api.can_use_feature('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','hse.copilot','hse.copilot.use',null),'Copilot requires both feature entitlement and functional permission');
select extensions.ok((select entitled from api.list_my_entitlements('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') where entitlement_kind='module' and entitlement_key='hse'),'member entitlement API reports their HSE module access');
select extensions.ok((select entitled from api.list_my_entitlements('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa') where entitlement_kind='feature' and entitlement_key='hse.copilot'),'member entitlement API reports exact membership Copilot access');
select extensions.throws_ok($$select * from api.list_my_entitlements('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')$$,'42501','member entitlement API rejects another tenant ID');
select set_config('request.jwt.claim.role','service_role',true);
set local role service_role;
select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb);
select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot','usage-test-key-0001',1,'request','{}'::jsonb);
select extensions.is((select count(*)::integer from core.usage_events where idempotency_key='usage-test-key-0001'),1,'usage retry with same idempotency key creates one event');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot','usage-test-key-0001',2,'request','{}'::jsonb)$$,'23505','idempotency key cannot be reused with different usage');
select extensions.throws_ok($$select api.record_feature_usage('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000002','hse.copilot','usage-test-key-0002',1,'request','{"prompt":"not allowed"}'::jsonb)$$,'42501','usage ledger rejects prompt content');
create temp table invitation_capture(invitation_id uuid,token text) on commit drop;
insert into invitation_capture select invitation_id,token from api.create_invitation('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','other@example.test','company_admin','00000000-0000-0000-0000-000000000002',interval '7 days');
select extensions.is((select octet_length(token_hash)::integer from iam.invitations where id=(select invitation_id from invitation_capture)),32,'invitation persists only a 32-byte hash');
select extensions.ok(not exists(select 1 from information_schema.columns where table_schema='iam' and table_name='invitations' and column_name='token'),'invitation schema has no raw-token column');
select extensions.lives_ok($$select api.accept_invitation((select token from invitation_capture),'00000000-0000-0000-0000-000000000005')$$,'verified matching Auth email accepts invitation');
select extensions.is((select member_role from iam.memberships where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' and user_id='00000000-0000-0000-0000-000000000005'),'company_admin'::text,'invitation provisions only the intended management level');
select extensions.throws_ok($$select api.accept_invitation((select token from invitation_capture),'00000000-0000-0000-0000-000000000005')$$,'22023','accepted invitation token cannot be replayed');
select api.create_invoice_draft('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','TEST-INV-1','USD',now()-interval '1 day',now()+interval '1 day');
select extensions.lives_ok($$select api.invoice_usage_event((select id from core.usage_events where idempotency_key='usage-test-key-0001'),(select id from core.invoices where invoice_number='TEST-INV-1'),'Synthetic test usage')$$,'one usage event can be invoiced');
select extensions.lives_ok($$select api.invoice_usage_event((select id from core.usage_events where idempotency_key='usage-test-key-0001'),(select id from core.invoices where invoice_number='TEST-INV-1'),'Synthetic test usage')$$,'repeated invoicing request is safe');
select extensions.is((select count(*)::integer from core.invoice_items where usage_event_id=(select id from core.usage_events where idempotency_key='usage-test-key-0001')),1,'usage event is invoiced at most once');
select extensions.is((select total_minor from core.invoices where invoice_number='TEST-INV-1'),123::bigint,'invoice uses exact minor-unit rate snapshot');
reset role;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000001',true);
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by)
 values('40000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','{"en":"Test","ar":"اختبار"}','test','published',1,'{}','10000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by)
 values('50000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','40000000-0000-0000-0000-000000000001',1,'{}','00000000-0000-0000-0000-000000000001');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id,status,current_stage,submitted_at)
 values('60000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','30000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','Approval test','10000000-0000-0000-0000-000000000002','submitted','reviewer_1',now()),
 ('60000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','30000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','Return test','10000000-0000-0000-0000-000000000002','submitted','reviewer_1',now());
insert into iam.task_assignments(tenant_id,membership_id,task_kind,task_id,assigned_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','inspection','60000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,'inspection','60000000-0000-0000-0000-000000000001'),'task assignment does not bypass missing site access');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,'inspection','60000000-0000-0000-0000-000000000001'),'assigned task becomes visible only after site scope also passes');
insert into iam.org_unit_access(tenant_id,membership_id,org_unit_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','30000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001');
select extensions.ok(private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000001'::uuid,false,null,null),'org-unit grant allows its exact unit');
select extensions.ok(not private.has_hse_permission('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000005','hse.inspections.read','30000000-0000-0000-0000-000000000003'::uuid,false,null,null),'site grant does not override a different org-unit scope');
insert into iam.membership_roles(tenant_id,membership_id,role_id,granted_by)
select 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003',id,'00000000-0000-0000-0000-000000000001' from iam.roles where role_key='reviewer_1' and tenant_id is null;
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','10000000-0000-0000-0000-000000000003','30000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000004',true);
select extensions.lives_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000001','reviewer_1','approved','10000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004',1)$$,'first reviewer approval advances to reviewer 2');
select extensions.is((select current_stage from hse.inspections where id='60000000-0000-0000-0000-000000000001'),'reviewer_2'::text,'review approval updates workflow stage');
select extensions.lives_ok($$insert into hse.inspection_reviews(tenant_id,inspection_id,stage,decision,actor_membership_id,actor_user_id,reason,revision) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','60000000-0000-0000-0000-000000000002','reviewer_1','returned','10000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004','Synthetic return reason',1)$$,'first reviewer can return an initially submitted inspection');
select extensions.is((select status from hse.inspections where id='60000000-0000-0000-0000-000000000002'),'returned'::text,'review return is applied');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is((select count(*)::integer from core.tenants),1,'tenant RLS limits employee to own company');
select extensions.is((with changed as (update iam.membership_roles set revoked_at=now() where membership_id='10000000-0000-0000-0000-000000000002' returning id) select count(*)::integer from changed),0,'employee cannot change role assignments');
reset role;
select extensions.ok(not has_table_privilege('authenticated','hse.follow_ups','DELETE'),'authenticated has no hard-delete privilege');
select extensions.throws_ok($$delete from audit.events where id=(select max(id) from audit.events)$$,'42501','audit ledger rejects hard delete');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000007',true);
set local role authenticated;
select extensions.throws_ok($$select api.manage_subowner('00000000-0000-0000-0000-000000000007',false)$$,'42501','Subowner cannot deactivate itself or manage operator roster');
reset role;
select * from extensions.finish();
rollback;
