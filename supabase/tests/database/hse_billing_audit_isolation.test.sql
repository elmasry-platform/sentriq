-- Cross-tenant isolation for HSE records, billing tables and the audit log, plus audit immutability.
-- Fixture: tenant A and tenant B both have the hse module and one employee with the same tenant-wide read role
-- (inspections, findings, actions, evidence, forms, audit) and write on findings. Data exists only in tenant A.
-- Tenant A's reader proves the policies let a legitimate reader through; tenant B's reader must still see nothing.
-- Billing tables (core.invoices, core.payments) are readable by platform operators only, so tenant readers see 0 by design.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(46);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000009a1','authenticated','authenticated','iso-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a2','authenticated','authenticated','iso-reader-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a3','authenticated','authenticated','iso-reader-b@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000009a1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values ('9a000000-0000-0000-0000-00000000000a','Isolation A','00000000-0000-0000-0000-0000000009a1'),('9b000000-0000-0000-0000-00000000000b','Isolation B','00000000-0000-0000-0000-0000000009a1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('91000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009a2','employee','active','iso-reader-a@example.test'),
 ('91000000-0000-0000-0000-000000000002','9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009a3','employee','active','iso-reader-b@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by)
 select x,'hse','active','00000000-0000-0000-0000-0000000009a1' from (values ('9a000000-0000-0000-0000-00000000000a'::uuid),('9b000000-0000-0000-0000-00000000000b'::uuid)) v(x);
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
 select e.tenant_id,e.module_key,e.created_at,'infinity'::timestamptz,e.changed_by,'Synthetic isolation fixture','complimentary','legacy_backfill',e.id
 from core.tenant_entitlements e where e.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b') and e.module_key='hse';
insert into core.sites(id,tenant_id,name,code) values
 ('93000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','Iso Site A','IA'),
 ('93000000-0000-0000-0000-000000000002','9b000000-0000-0000-0000-00000000000b','Iso Site B','IB');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values
 ('9a000000-0000-0000-0000-00000000000a','91000000-0000-0000-0000-000000000001','93000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-0000000009a1'),
 ('9b000000-0000-0000-0000-00000000000b','91000000-0000-0000-0000-000000000002','93000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-0000000009a1');
-- Same tenant-wide reader role in both tenants.
insert into iam.roles(tenant_id,role_key,label,role_family,created_by)
 select x,'iso_reader','Isolation Reader','employee','00000000-0000-0000-0000-0000000009a1' from (values ('9a000000-0000-0000-0000-00000000000a'::uuid),('9b000000-0000-0000-0000-00000000000b'::uuid)) v(x);
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
 select r.id,p.k,'tenant',true,p.w from iam.roles r cross join (values
  ('hse.inspections.read',false),('hse.findings.read',false),('hse.findings.manage',true),('hse.actions.read',false),
  ('hse.evidence.read',false),('hse.forms.read',false),('hse.audit.read',false)) p(k,w)
 where r.role_key='iso_reader' and r.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by,published_at)
 select tenant_id,id,1,role_family,'published','00000000-0000-0000-0000-0000000009a1',now() from iam.roles where role_key='iso_reader' and tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read,can_write)
 select rv.id,rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write
 from iam.role_versions rv join iam.role_permissions rp on rp.role_id=rv.role_id
 join iam.roles r on r.id=rv.role_id where r.role_key='iso_reader' and r.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
 select r.tenant_id,m.id,r.id,rv.id,'00000000-0000-0000-0000-0000000009a1'
 from iam.roles r join iam.role_versions rv on rv.role_id=r.id and rv.version_no=1
 join iam.memberships m on m.tenant_id=r.tenant_id and m.id in ('91000000-0000-0000-0000-000000000001','91000000-0000-0000-0000-000000000002')
 where r.role_key='iso_reader';

-- Fixture rows bypass workflow triggers (creation rules are tested elsewhere); isolation is tested below with triggers on.
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

select extensions.is((select count(*)::int from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname in ('core','iam','hse','audit') and c.relkind in ('r','p','v','m','f') and (has_table_privilege('anon',c.oid,'select') or has_table_privilege('anon',c.oid,'insert') or has_table_privilege('anon',c.oid,'update') or has_table_privilege('anon',c.oid,'delete'))),0,'I01 anon has no privilege on any relation in core, iam, hse, audit');
select extensions.is((select count(*)::int from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname in ('core','iam','hse','audit') and c.relkind in ('r','p') and (has_table_privilege('authenticated',c.oid,'delete') or has_table_privilege('authenticated',c.oid,'truncate'))),0,'I02 authenticated has no DELETE or TRUNCATE on any table in core, iam, hse, audit');
select extensions.is((select count(*)::int from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','p') and (n.nspname='audit' or (n.nspname='core' and c.relname not in ('tenants','org_units','sites','tenant_domains'))) and (has_table_privilege('authenticated',c.oid,'insert') or has_table_privilege('authenticated',c.oid,'update'))),0,'I03 authenticated cannot write audit tables or any core table other than the four structure tables (billing and entitlements are function-only)');
select extensions.is((select count(*)::int from hse.inspections where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I04 fixture: A inspection exists');
select extensions.is((select count(*)::int from hse.findings where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I05 fixture: A row exists in hse.findings');
select extensions.is((select count(*)::int from hse.corrective_actions where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I06 fixture: A row exists in hse.corrective_actions');
select extensions.is((select count(*)::int from hse.action_updates where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I07 fixture: A row exists in hse.action_updates');
select extensions.is((select count(*)::int from hse.follow_ups where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I08 fixture: A row exists in hse.follow_ups');
select extensions.is((select count(*)::int from hse.evidence_files where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I09 fixture: A row exists in hse.evidence_files');
select extensions.is((select count(*)::int from hse.form_templates where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I10 fixture: A row exists in hse.form_templates');
select extensions.is((select count(*)::int from core.invoices where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I11 fixture: A row exists in core.invoices');
select extensions.is((select count(*)::int from core.payments where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I12 fixture: A row exists in core.payments');
select extensions.is((select count(*)::int from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a' and action_key='iso.test'),1,'I13 fixture: A audit row exists');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a2',true);
set local role authenticated;
select extensions.is((select count(*)::int from hse.inspections where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I14 positive control: A reader sees own hse.inspections');
select extensions.is((select count(*)::int from hse.findings where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I15 positive control: A reader sees own hse.findings');
select extensions.is((select count(*)::int from hse.corrective_actions where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I16 positive control: A reader sees own hse.corrective_actions');
select extensions.is((select count(*)::int from hse.action_updates where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I17 positive control: A reader sees own hse.action_updates');
select extensions.is((select count(*)::int from hse.follow_ups where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I18 positive control: A reader sees own hse.follow_ups');
select extensions.is((select count(*)::int from hse.evidence_files where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I19 positive control: A reader sees own hse.evidence_files');
select extensions.is((select count(*)::int from hse.form_templates where tenant_id='9a000000-0000-0000-0000-00000000000a'),1,'I20 positive control: A reader sees own hse.form_templates');
select extensions.is((select count(*)::int from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a' and action_key='iso.test'),1,'I21 positive control: A reader sees own audit.events');
select extensions.is((select count(*)::int from core.invoices where tenant_id='9a000000-0000-0000-0000-00000000000a')+(select count(*)::int from core.payments where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I22 billing tables are operator-only: a tenant reader sees none');
with u as (update hse.findings set title='Iso finding edited' where id='97000000-0000-0000-0000-000000000001' returning 1) select extensions.is((select count(*)::int from u),1,'I23 positive control: A reader with findings.manage updates own finding');
select extensions.throws_ok($$update audit.events set summary='{"x":1}' where tenant_id='9a000000-0000-0000-0000-00000000000a'$$,'42501',null,'I24 A reader cannot update audit events (stopped by missing UPDATE grant)');
select extensions.throws_ok($$delete from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a'$$,'42501',null,'I25 A reader cannot delete audit events (stopped by missing DELETE grant)');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a3',true);
select extensions.is((select count(*)::int from hse.inspections where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I26 B reader cannot read A rows in hse.inspections');
select extensions.is((select count(*)::int from hse.findings where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I27 B reader cannot read A rows in hse.findings');
select extensions.is((select count(*)::int from hse.corrective_actions where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I28 B reader cannot read A rows in hse.corrective_actions');
select extensions.is((select count(*)::int from hse.action_updates where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I29 B reader cannot read A rows in hse.action_updates');
select extensions.is((select count(*)::int from hse.follow_ups where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I30 B reader cannot read A rows in hse.follow_ups');
select extensions.is((select count(*)::int from hse.evidence_files where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I31 B reader cannot read A rows in hse.evidence_files');
select extensions.is((select count(*)::int from hse.form_templates where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I32 B reader cannot read A rows in hse.form_templates');
select extensions.is((select count(*)::int from audit.events where tenant_id='9a000000-0000-0000-0000-00000000000a' and action_key='iso.test'),0,'I33 B reader cannot read A rows in audit.events');
select extensions.is((select count(*)::int from core.invoices where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I34 B reader cannot read A rows in core.invoices');
select extensions.is((select count(*)::int from core.payments where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I35 B reader cannot read A rows in core.payments');
select extensions.is((select count(*)::int from hse.findings where tenant_id='9a000000-0000-0000-0000-00000000000a'),0,'I36 B reader sees no A finding even though B has the same role and module');
select extensions.throws_ok($$insert into hse.findings(tenant_id,site_id,inspection_id,title,created_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-000000000001','96000000-0000-0000-0000-000000000001','Injected','00000000-0000-0000-0000-0000000009a3')$$,'42501',null,'I37 B cannot insert a finding into tenant A (RLS with-check or trigger, SQLSTATE 42501)');
select extensions.throws_ok($$insert into hse.findings(tenant_id,site_id,inspection_id,title,created_by) values('9b000000-0000-0000-0000-00000000000b','93000000-0000-0000-0000-000000000001','96000000-0000-0000-0000-000000000001','Cross','00000000-0000-0000-0000-0000000009a3')$$,'42501',null,'I38 B cannot insert a B finding that points at A site and inspection');
select extensions.throws_ok($$insert into core.invoices(tenant_id,invoice_number,status,currency,period_start,period_end) values('9b000000-0000-0000-0000-00000000000b','X','draft','USD','2026-01-01','2026-02-01')$$,'42501',null,'I39 tenant user cannot create invoices (missing INSERT grant)');
select extensions.throws_ok($$insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary) values('9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009a3','tenant','forged','x',gen_random_uuid(),'{}')$$,'42501',null,'I40 tenant user cannot write audit events (missing INSERT grant)');
with u as (update hse.findings set title='Hijack' where id='97000000-0000-0000-0000-000000000001' returning 1) select extensions.is((select count(*)::int from u),0,'I41 B cannot update an A finding (RLS hides the row)');
reset role;
select extensions.throws_ok($$update audit.events set summary='{"x":1}' where action_key='iso.test'$$,'42501','audit events are append-only','I42 audit update blocked by the append-only trigger, even for the table owner');
select extensions.throws_ok($$delete from audit.events where action_key='iso.test'$$,'42501','audit events are append-only','I43 audit delete blocked by the append-only trigger, even for the table owner');
select extensions.is((select count(*)::int from audit.events where action_key='iso.test'),1,'I44 audit row still present');
select extensions.is((select count(*)::int from hse.findings where id='97000000-0000-0000-0000-000000000001' and title='Iso finding edited'),1,'I45 A finding changed only by its own reader');
select extensions.is((select count(*)::int from hse.findings where title in ('Injected','Cross','Hijack')),0,'I46 no injected or hijacked findings exist');
select * from extensions.finish();
rollback;
