-- Cross-tenant isolation for HSE records, billing tables and the audit log, plus audit immutability.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(26);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000009a1','authenticated','authenticated','iso-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a2','authenticated','authenticated','iso-admin-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a3','authenticated','authenticated','iso-admin-b@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000009a1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values
 ('9a000000-0000-0000-0000-00000000000a','Isolation A','00000000-0000-0000-0000-0000000009a1'),
 ('9b000000-0000-0000-0000-00000000000b','Isolation B','00000000-0000-0000-0000-0000000009a1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('91000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009a2','company_superadmin','active','iso-admin-a@example.test'),
 ('91000000-0000-0000-0000-000000000002','9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009a3','company_superadmin','active','iso-admin-b@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by)
 values('9a000000-0000-0000-0000-00000000000a','hse','active','00000000-0000-0000-0000-0000000009a1');
insert into core.sites(id,tenant_id,name,code) values
 ('93000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','Iso Site A','IA'),
 ('93000000-0000-0000-0000-000000000002','9b000000-0000-0000-0000-00000000000b','Iso Site B','IB');
-- Fixture rows bypass workflow triggers (they test creation rules elsewhere); isolation is tested below with triggers on.
set local session_replication_role = replica;
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by)
 values('94000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','{"en":"T"}','test','published',1,'{}','91000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-0000000009a1');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by)
 values('95000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-000000000001',1,'{}','00000000-0000-0000-0000-0000000009a1');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id,status,current_stage,submitted_at)
 values('96000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-000000000001','94000000-0000-0000-0000-000000000001','95000000-0000-0000-0000-000000000001','Iso inspection','91000000-0000-0000-0000-000000000001','submitted','reviewer_1',now());
insert into hse.findings(id,tenant_id,site_id,inspection_id,title,created_by)
 values('97000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-000000000001','96000000-0000-0000-0000-000000000001','Iso finding','00000000-0000-0000-0000-0000000009a1');
insert into hse.corrective_actions(id,tenant_id,site_id,finding_id,inspection_id,title,owner_membership_id,created_by)
 values('98000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-000000000001','97000000-0000-0000-0000-000000000001','96000000-0000-0000-0000-000000000001','Iso action','91000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-0000000009a1');
insert into hse.action_updates(tenant_id,action_id,status) values('9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-000000000001','in_progress');
insert into hse.follow_ups(tenant_id,action_id,title,owner_membership_id,due_at)
 values('9a000000-0000-0000-0000-00000000000a','98000000-0000-0000-0000-000000000001','Iso follow-up','91000000-0000-0000-0000-000000000001',now()+interval '7 days');
insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by)
 values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-000000000001','finding','97000000-0000-0000-0000-000000000001','iso/key','iso.png','image/png',10,'00000000-0000-0000-0000-0000000009a1');
insert into core.invoices(id,tenant_id,invoice_number,status,currency,period_start,period_end)
 values('99000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','ISO-1','draft','USD','2026-01-01','2026-02-01');
insert into core.payments(tenant_id,invoice_id,provider,provider_reference,status,amount_minor,currency)
 values('9a000000-0000-0000-0000-00000000000a','99000000-0000-0000-0000-000000000001','test','iso-ref','pending',0,'USD');
insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values('9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009a1','tenant','iso.test','iso',gen_random_uuid(),'{}');

set local session_replication_role = origin;

-- Catalog guarantees
select extensions.is((select count(*)::int from information_schema.role_table_grants where grantee='anon' and table_schema in ('core','iam','hse','audit')),0,'I01 anon has no table privileges');
select extensions.is((select count(*)::int from information_schema.role_table_grants where grantee='authenticated' and table_schema in ('core','audit') and table_name in ('invoices','invoice_items','payments','usage_events','subscriptions','subscription_items','plans','plan_entitlements','entitlement_grants','events') and privilege_type<>'SELECT'),0,'I02 authenticated cannot write billing or audit tables directly');

-- Fixture present (as owner), so the zero counts below are not vacuous
select extensions.is((select count(*)::int from hse.inspections where tenant_id='9a000000-0000-0000-0000-00000000000a')
 + (select count(*)::int from hse.findings where tenant_id='9a000000-0000-0000-0000-00000000000a')
 + (select count(*)::int from hse.corrective_actions where tenant_id='9a000000-0000-0000-0000-00000000000a')
 + (select count(*)::int from core.invoices where tenant_id='9a000000-0000-0000-0000-00000000000a')
 + (select count(*)::int from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a' and action_key='iso.test'),5,'I19 fixture rows exist for tenant A (B zero-counts are not vacuous)');

-- Tenant B admin sees nothing of tenant A
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a3',true);
set local role authenticated;
select extensions.is((select count(*)::int from hse.inspections where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I03 B cannot read A inspections');
select extensions.is((select count(*)::int from hse.findings where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I04 B cannot read A findings');
select extensions.is((select count(*)::int from hse.corrective_actions where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I05 B cannot read A corrective actions');
select extensions.is((select count(*)::int from hse.action_updates where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I06 B cannot read A action updates');
select extensions.is((select count(*)::int from hse.follow_ups where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I07 B cannot read A follow-ups');
select extensions.is((select count(*)::int from hse.evidence_files where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I08 B cannot read A evidence files');
select extensions.is((select count(*)::int from hse.form_templates where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I09 B cannot read A form templates');
select extensions.is((select count(*)::int from core.invoices where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I10 B cannot read A invoices');
select extensions.is((select count(*)::int from core.payments where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I11 B cannot read A payments');
select extensions.is((select count(*)::int from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I12 B cannot read A audit events');
select extensions.throws_ok($$insert into hse.findings(tenant_id,site_id,inspection_id,title,created_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-000000000001','96000000-0000-0000-0000-000000000001','Injected','00000000-0000-0000-0000-0000000009a3')$$,'42501',null,'I13 B cannot insert a finding into A');
select extensions.throws_ok($$insert into hse.findings(tenant_id,site_id,inspection_id,title,created_by) values('9b000000-0000-0000-0000-00000000000b','93000000-0000-0000-0000-000000000001','96000000-0000-0000-0000-000000000001','Cross','00000000-0000-0000-0000-0000000009a3')$$,null,null,'I14 B cannot insert into B using A site and inspection');
select extensions.throws_ok($$insert into core.invoices(tenant_id,invoice_number,status,currency,period_start,period_end) values('9b000000-0000-0000-0000-00000000000b','X','draft','USD','2026-01-01','2026-02-01')$$,'42501',null,'I15 tenant admin cannot create invoices');
select extensions.throws_ok($$insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary) values('9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009a3','tenant','forged','x',gen_random_uuid(),'{}')$$,'42501',null,'I16 tenant admin cannot write audit events');
with u as (update hse.findings set title='Hijack' where id='97000000-0000-0000-0000-000000000001' returning 1)
select extensions.is((select count(*)::int from u),0,'I17 B cannot update an A finding');
select extensions.throws_ok($$delete from hse.findings where id='97000000-0000-0000-0000-000000000001'$$,'42501',null,'I18 authenticated has no DELETE on findings');

-- Tenant A admin cannot rewrite the audit log
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a2',true);
select extensions.throws_ok($$update audit.events set summary='{"x":1}' where tenant_id='9a000000-0000-0000-0000-00000000000a'$$,'42501',null,'I20 A admin cannot update audit events');
select extensions.throws_ok($$delete from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a'$$,'42501',null,'I21 A admin cannot delete audit events');
reset role;

-- Immutability holds even for the table owner
select extensions.throws_ok($$update audit.events set summary='{"x":1}' where action_key='iso.test'$$,null,null,'I22 audit update blocked by trigger');
select extensions.throws_ok($$delete from audit.events where action_key='iso.test'$$,null,null,'I23 audit delete blocked by trigger');
select extensions.is((select count(*)::int from audit.events where action_key='iso.test'),1,'I24 audit row still present');
select extensions.is((select count(*)::int from hse.findings where id='97000000-0000-0000-0000-000000000001' and title='Iso finding'),1,'I25 A finding unchanged after B attempts');
select extensions.is((select count(*)::int from hse.findings where title in ('Injected','Cross')),0,'I26 no injected findings exist');

select * from extensions.finish();
rollback;
