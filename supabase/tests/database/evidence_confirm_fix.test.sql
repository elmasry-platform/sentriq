-- AFTER DRAFT 046: hse.evidence_files write guards + confirmation RPC. W03/W04 flipped from KNOWN GAP to denied.
-- hse.evidence_files write guards: who may create or change an evidence record, and what cannot be changed.
-- Fixture: tenant A and B each have the hse module. A has an uploader (upload permission) and a reader (read permission);
-- B has an uploader. Object keys are '<tenant>/<site>/<file>', as the policies require.
begin;
-- Local stub storage has only owner; real Supabase has metadata. Harmless no-op on real Supabase.
-- Local stub only: real Supabase storage already has metadata and owner_id (and its tables are not owned by postgres).
do $$ begin
  if not exists (select 1 from information_schema.columns where table_schema='storage' and table_name='objects' and column_name='metadata') then
    execute 'alter table storage.objects add column metadata jsonb'; end if;
  if not exists (select 1 from information_schema.columns where table_schema='storage' and table_name='objects' and column_name='owner_id') then
    execute 'alter table storage.objects add column owner_id text'; end if;
end $$;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(36);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000009c1','authenticated','authenticated','ev-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c2','authenticated','authenticated','ev-up-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c3','authenticated','authenticated','ev-read-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c5','authenticated','authenticated','ev-up2-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c4','authenticated','authenticated','ev-up-b@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000009c1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values ('9a000000-0000-0000-0000-00000000000a','Evidence A','00000000-0000-0000-0000-0000000009c1'),('9b000000-0000-0000-0000-00000000000b','Evidence B','00000000-0000-0000-0000-0000000009c1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('92000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009c2','employee','active','ev-up-a@example.test'),
 ('92000000-0000-0000-0000-000000000002','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009c3','employee','active','ev-read-a@example.test'),
 ('92000000-0000-0000-0000-000000000004','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009c5','employee','active','ev-up2-a@example.test'),
 ('92000000-0000-0000-0000-000000000003','9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009c4','employee','active','ev-up-b@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by) select x,'hse','active','00000000-0000-0000-0000-0000000009c1' from (values ('9a000000-0000-0000-0000-00000000000a'::uuid),('9b000000-0000-0000-0000-00000000000b'::uuid)) v(x);
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
 select e.tenant_id,e.module_key,e.created_at,'infinity'::timestamptz,e.changed_by,'Synthetic evidence fixture','complimentary','legacy_backfill',e.id
 from core.tenant_entitlements e where e.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b') and e.module_key='hse';
insert into core.sites(id,tenant_id,name,code) values ('93000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','Ev Site A','EA'),('93000000-0000-0000-0000-0000000000b1','9b000000-0000-0000-0000-00000000000b','Ev Site B','EB');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values
 ('9a000000-0000-0000-0000-00000000000a','92000000-0000-0000-0000-000000000004','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009c1'),
 ('9a000000-0000-0000-0000-00000000000a','92000000-0000-0000-0000-000000000001','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009c1'),('9a000000-0000-0000-0000-00000000000a','92000000-0000-0000-0000-000000000002','93000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000009c1'),('9b000000-0000-0000-0000-00000000000b','92000000-0000-0000-0000-000000000003','93000000-0000-0000-0000-0000000000b1','00000000-0000-0000-0000-0000000009c1');
insert into iam.roles(tenant_id,role_key,label,role_family,created_by) values
 ('9a000000-0000-0000-0000-00000000000a','ev_uploader','Evidence Uploader','employee','00000000-0000-0000-0000-0000000009c1'),('9a000000-0000-0000-0000-00000000000a','ev_reader','Evidence Reader','employee','00000000-0000-0000-0000-0000000009c1'),('9b000000-0000-0000-0000-00000000000b','ev_uploader','Evidence Uploader','employee','00000000-0000-0000-0000-0000000009c1');
insert into iam.role_permissions(role_id,permission_key,scope_kind,can_read,can_write)
 select r.id,p.k,'tenant',true,p.w from iam.roles r join (values ('ev_uploader','hse.evidence.upload',true),('ev_reader','hse.evidence.read',false)) p(rk,k,w) on p.rk=r.role_key
 where r.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by,published_at)
 select tenant_id,id,1,role_family,'published','00000000-0000-0000-0000-0000000009c1',now() from iam.roles where role_key in ('ev_uploader','ev_reader') and tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read,can_write)
 select rv.id,rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write from iam.role_versions rv join iam.role_permissions rp on rp.role_id=rv.role_id join iam.roles r on r.id=rv.role_id
 where r.role_key in ('ev_uploader','ev_reader') and r.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b');
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;
insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,granted_by)
 select r.tenant_id,m.id,r.id,rv.id,'00000000-0000-0000-0000-0000000009c1' from iam.roles r join iam.role_versions rv on rv.role_id=r.id and rv.version_no=1
 join iam.memberships m on m.tenant_id=r.tenant_id
 where (r.role_key='ev_uploader' and m.user_id in ('00000000-0000-0000-0000-0000000009c5','00000000-0000-0000-0000-0000000009c2','00000000-0000-0000-0000-0000000009c4')) or (r.role_key='ev_reader' and m.user_id='00000000-0000-0000-0000-0000000009c3');
-- A finding in tenant A so evidence has a record to link to (fixture bypasses workflow triggers).
set local session_replication_role = replica;
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values('94000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','{"en":"T"}','t','published',1,'{}','92000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-0000000009c1');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by) values('95000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-0000000000a1',1,'{}','00000000-0000-0000-0000-0000000009c1');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id,status,current_stage,submitted_at) values('96000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','94000000-0000-0000-0000-0000000000a1','95000000-0000-0000-0000-0000000000a1','Ev insp','92000000-0000-0000-0000-000000000001','submitted','reviewer_1',now());
insert into hse.findings(id,tenant_id,site_id,inspection_id,title,created_by) values('97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','96000000-0000-0000-0000-0000000000a1','Ev finding','00000000-0000-0000-0000-0000000009c1');
insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by,status) values
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-charset.png','x.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-octet.png','x.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-ownerid.png','x.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-owner.png','x.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-size.png','x.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-mime.png','x.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png','p.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png','c.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','confirmed'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-new.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed-new.png','cn.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','confirmed'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/rejected-new.png','r.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','rejected'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9b000000-0000-0000-0000-00000000000b/93000000-0000-0000-0000-0000000000b1/wrongpath.png','w.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/reader-own.png','ro.png','image/png',10,'00000000-0000-0000-0000-0000000009c3','pending');
insert into core.sites(id,tenant_id,name,code) values ('93000000-0000-0000-0000-0000000000a2','9a000000-0000-0000-0000-00000000000a','Ev Site A2 (no access for uploader)','EA2');
insert into hse.findings(id,tenant_id,site_id,inspection_id,title,created_by) values('97000000-0000-0000-0000-0000000000a2','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a2','96000000-0000-0000-0000-0000000000a1','Ev finding at A2','00000000-0000-0000-0000-0000000009c1');
insert into storage.buckets(id,name,public) values ('sentriq-hse-evidence','sentriq-hse-evidence',false) on conflict do nothing;
insert into storage.objects(bucket_id,name,owner,metadata) values
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png','00000000-0000-0000-0000-0000000009c2','{"size":10,"mimetype":"image/png"}'),
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-owner.png','00000000-0000-0000-0000-0000000009c3','{"size":10,"mimetype":"image/png"}'),
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-size.png','00000000-0000-0000-0000-0000000009c2','{"size":999,"mimetype":"image/png"}'),
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-mime.png','00000000-0000-0000-0000-0000000009c2','{"size":10,"mimetype":"image/jpeg"}'),
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-charset.png','00000000-0000-0000-0000-0000000009c2','{"size":10,"mimetype":"Image/PNG; charset=binary"}'),
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-octet.png','00000000-0000-0000-0000-0000000009c2','{"size":10,"mimetype":"application/octet-stream"}');
insert into storage.objects(bucket_id,name,owner,owner_id,metadata) values ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-ownerid.png','00000000-0000-0000-0000-0000000009c2','00000000-0000-0000-0000-0000000009c3','{"size":10,"mimetype":"image/png"}');
insert into storage.objects(bucket_id,name,owner,metadata) values ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png','00000000-0000-0000-0000-0000000009c2','{"size":10,"mimetype":"image/png"}');
set local session_replication_role = origin;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
set local role authenticated;
select extensions.lives_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c2')$$,'W01 uploader creates a pending evidence row for its own site and record');
select extensions.is((select status from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png'),'pending','W02 new rows start pending');
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by,status) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w2.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','confirmed')$$,'42501','evidence status is set by confirmation only','W03 FIXED: the uploader cannot create an already confirmed row');
select extensions.throws_ok($$update hse.evidence_files set status='confirmed' where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png'$$,'42501','evidence status is set by confirmation only','W04 FIXED: the uploader cannot confirm its own evidence by direct update');
select extensions.throws_ok($$update hse.evidence_files set file_name='other.png' where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png'$$,'23514','immutable field changed','W05 file metadata is immutable after creation');
select extensions.throws_ok($$update hse.evidence_files set uploaded_by='00000000-0000-0000-0000-0000000009c3' where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png'$$,'23514','immutable field changed','W06 uploader cannot be reassigned');
select extensions.throws_ok($$delete from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png'$$,'42501',null,'W07 authenticated cannot delete evidence rows (no DELETE grant)');
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w3.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c3')$$,'42501',null,'W08 a user cannot create evidence in the name of another uploader');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c3',true);
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w4.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c3')$$,'42501',null,'W09 reader without hse.evidence.upload cannot create evidence');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c4',true);
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w5.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c4')$$,'42501',null,'W10 tenant B uploader cannot create evidence in tenant A');
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9b000000-0000-0000-0000-00000000000b','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9b000000-0000-0000-0000-00000000000b/93000000-0000-0000-0000-0000000000a1/w6.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c4')$$,'23503','evidence target is invalid for tenant/site','W11 tenant B row pointing at a tenant A site is rejected');
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9b000000-0000-0000-0000-00000000000b','93000000-0000-0000-0000-0000000000b1','finding','97000000-0000-0000-0000-0000000000a1','9b000000-0000-0000-0000-00000000000b/93000000-0000-0000-0000-0000000000b1/w7.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c4')$$,'23503','evidence target is invalid for tenant/site','W12 tenant B row pointing at a tenant A finding is rejected');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a2','finding','97000000-0000-0000-0000-0000000000a2','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a2/w8.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c2')$$,'42501',null,'W14 same tenant, correct site and record, but the uploader has no access to that site: denied');
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a2','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w9.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c2')$$,'23503','evidence target is invalid for tenant/site','W15 same tenant: uploader claims its own site but links a record that belongs to another site: rejected');
reset role;
select extensions.is((select count(*)::int from hse.evidence_files where tenant_id='9a000000-0000-0000-0000-00000000000a' and storage_key like '9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w%'),1,'W13 only the one row created by the uploader exists (W01); W03 created nothing; no cross-tenant rows');
select set_config('t.pid_seen',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png'),true);
select set_config('t.pid_new',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-new.png'),true);
select set_config('t.pid_w1',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/w1.png'),true);
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_w1')::uuid)$$,'22023','evidence object is not stored','R01 confirm is refused when the object is not in storage');
select extensions.lives_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_seen')::uuid)$$,'R02 positive control: the uploader confirms its own stored pending evidence through the RPC');
select extensions.is((select status from hse.evidence_files where id=current_setting('t.pid_seen')::uuid),'confirmed','R03 status is confirmed after the RPC');
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_seen')::uuid)$$,'22023','evidence is not pending','R04 confirming twice is refused');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c3',true);
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_new')::uuid)$$,'42501','insufficient_privilege','R05 a reader without upload permission cannot confirm');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c4',true);
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_new')::uuid)$$,'42501','insufficient_privilege','R06 a tenant B uploader cannot confirm tenant A evidence');
reset role;
set local role anon;
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_new')::uuid)$$,'42501','permission denied for function confirm_evidence','R07 anon has no EXECUTE on the RPC');
reset role;
select extensions.is((select count(*)::int from audit.events where action_key='hse.evidence.confirmed' and record_id=current_setting('t.pid_seen')::uuid),1,'R08 exactly one audit event was written for the confirmation');
select extensions.is((select status from hse.evidence_files where id=current_setting('t.pid_new')::uuid),'pending','R09 refused attempts left the other row pending');
select set_config('t.pid_mowner',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-owner.png'),true);
select set_config('t.pid_msize',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-size.png'),true);
select set_config('t.pid_mmime',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-mime.png'),true);
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_mowner')::uuid)$$,'22023','evidence object does not match the record','R10 object owned by someone else is refused');
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_msize')::uuid)$$,'22023','evidence object does not match the record','R11 object size differs from the record: refused');
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_mmime')::uuid)$$,'22023','evidence object does not match the record','R12 object mime type differs from the record: refused');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c5',true);
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_mowner')::uuid)$$,'42501','insufficient_privilege','R13 same tenant and site, has upload permission, but is not the uploader: cannot confirm');
select extensions.throws_ok($$insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by,status) values('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/c5-conf.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c5','confirmed')$$,'42501','evidence status is set by confirmation only','R14 a second uploader cannot insert a confirmed row either');
reset role;
-- service_role and the owner bypass the guard. This documents the bypass (back-office path), it is not a promise.
select extensions.lives_ok($$update hse.evidence_files set status='confirmed' where id=current_setting('t.pid_msize')::uuid$$,'R15 BYPASS (documented): the database owner (migrations, back office) can set status directly');
reset role;
select extensions.is((select status from hse.evidence_files where id=current_setting('t.pid_mowner')::uuid),'pending','R17 refused attempts left the mismatched row pending');
select set_config('t.pid_chs',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-charset.png'),true);
select set_config('t.pid_oct',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-octet.png'),true);
select set_config('t.pid_oid',(select id::text from hse.evidence_files where storage_key='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/m-ownerid.png'),true);
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
select extensions.lives_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_chs')::uuid)$$,'R18 mime type with different case and a charset suffix is accepted as the same base type');
select extensions.lives_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_oct')::uuid)$$,'R19 documented: application/octet-stream from storage is accepted (size and owner still checked)');
select extensions.throws_ok($$select api.confirm_evidence('9a000000-0000-0000-0000-00000000000a', current_setting('t.pid_oid')::uuid)$$,'22023','evidence object does not match the record','R20 owner_id wins over the legacy owner column: owner_id of another user is refused');
reset role;
select extensions.is((select count(*)::int from pg_roles r where r.rolname not in ('postgres','authenticated','anon') and not r.rolsuper and r.rolname !~ '^pg_' and (has_table_privilege(r.oid,'hse.evidence_files','insert') or has_table_privilege(r.oid,'hse.evidence_files','update') or has_table_privilege(r.oid,'hse.evidence_files','delete'))),0,'R21 no other role (service_role included) holds INSERT, UPDATE or DELETE on hse.evidence_files');
select extensions.ok(not has_table_privilege('service_role','hse.evidence_files','insert') and not has_table_privilege('service_role','hse.evidence_files','update') and not has_table_privilege('service_role','hse.evidence_files','delete'),'R22 service_role specifically has no write privilege on hse.evidence_files');
select * from extensions.finish();
rollback;
