-- Evidence files: storage.objects policies (read and upload) and hse.evidence_files writes.
-- Fixture: tenant A and B each have the hse module. A has an uploader (upload permission) and a reader (read permission);
-- B has an uploader. Object keys are '<tenant>/<site>/<file>', as the policies require.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(21);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000009c1','authenticated','authenticated','ev-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c2','authenticated','authenticated','ev-up-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c3','authenticated','authenticated','ev-read-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009c4','authenticated','authenticated','ev-up-b@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000009c1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values ('9a000000-0000-0000-0000-00000000000a','Evidence A','00000000-0000-0000-0000-0000000009c1'),('9b000000-0000-0000-0000-00000000000b','Evidence B','00000000-0000-0000-0000-0000000009c1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('92000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009c2','employee','active','ev-up-a@example.test'),
 ('92000000-0000-0000-0000-000000000002','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009c3','employee','active','ev-read-a@example.test'),
 ('92000000-0000-0000-0000-000000000003','9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009c4','employee','active','ev-up-b@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by) select x,'hse','active','00000000-0000-0000-0000-0000000009c1' from (values ('9a000000-0000-0000-0000-00000000000a'::uuid),('9b000000-0000-0000-0000-00000000000b'::uuid)) v(x);
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
 select e.tenant_id,e.module_key,e.created_at,'infinity'::timestamptz,e.changed_by,'Synthetic evidence fixture','complimentary','legacy_backfill',e.id
 from core.tenant_entitlements e where e.tenant_id in ('9a000000-0000-0000-0000-00000000000a','9b000000-0000-0000-0000-00000000000b') and e.module_key='hse';
insert into core.sites(id,tenant_id,name,code) values ('93000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','Ev Site A','EA'),('93000000-0000-0000-0000-0000000000b1','9b000000-0000-0000-0000-00000000000b','Ev Site B','EB');
insert into iam.site_access(tenant_id,membership_id,site_id,granted_by) values
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
 where (r.role_key='ev_uploader' and m.user_id in ('00000000-0000-0000-0000-0000000009c2','00000000-0000-0000-0000-0000000009c4')) or (r.role_key='ev_reader' and m.user_id='00000000-0000-0000-0000-0000000009c3');
-- A finding in tenant A so evidence has a record to link to (fixture bypasses workflow triggers).
set local session_replication_role = replica;
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values('94000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','{"en":"T"}','t','published',1,'{}','92000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-0000000009c1');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by) values('95000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','94000000-0000-0000-0000-0000000000a1',1,'{}','00000000-0000-0000-0000-0000000009c1');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id,status,current_stage,submitted_at) values('96000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','94000000-0000-0000-0000-0000000000a1','95000000-0000-0000-0000-0000000000a1','Ev insp','92000000-0000-0000-0000-000000000001','submitted','reviewer_1',now());
insert into hse.findings(id,tenant_id,site_id,inspection_id,title,created_by) values('97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','96000000-0000-0000-0000-0000000000a1','Ev finding','00000000-0000-0000-0000-0000000009c1');
insert into hse.evidence_files(tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by,status) values
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png','p.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png','c.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','confirmed'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-new.png','n.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed-new.png','cn.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','confirmed'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/rejected-new.png','r.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','rejected'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9b000000-0000-0000-0000-00000000000b/93000000-0000-0000-0000-0000000000b1/wrongpath.png','w.png','image/png',10,'00000000-0000-0000-0000-0000000009c2','pending'),
 ('9a000000-0000-0000-0000-00000000000a','93000000-0000-0000-0000-0000000000a1','finding','97000000-0000-0000-0000-0000000000a1','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/reader-own.png','ro.png','image/png',10,'00000000-0000-0000-0000-0000000009c3','pending');
insert into storage.buckets(id,name,public) values ('sentriq-hse-evidence','sentriq-hse-evidence',false) on conflict do nothing;
insert into storage.objects(bucket_id,name,owner) values
 ('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png','00000000-0000-0000-0000-0000000009c2'),('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png','00000000-0000-0000-0000-0000000009c2');
set local session_replication_role = origin;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
set local role authenticated;
select extensions.is((select count(*)::int from storage.objects where name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png'),1,'E01 uploader reads own pending object');
select extensions.is((select count(*)::int from storage.objects where name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png'),1,'E02 uploader reads a confirmed object');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c3',true);
select extensions.is((select count(*)::int from storage.objects where name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png'),1,'E03 reader with hse.evidence.read sees a confirmed object');
select extensions.is((select count(*)::int from storage.objects where name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png'),0,'E04 reader does not see a pending object of another user');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c4',true);
select extensions.is((select count(*)::int from storage.objects where name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png'),0,'E05 tenant B user cannot read A confirmed object');
select extensions.is((select count(*)::int from storage.objects where name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-seen.png'),0,'E06 tenant B user cannot read A pending object');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
select extensions.lives_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-new.png','00000000-0000-0000-0000-0000000009c2')$$,'E07 uploader may upload for its own pending row');
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed-new.png','00000000-0000-0000-0000-0000000009c2')$$,'42501',null,'E08 upload denied when the evidence row is already confirmed');
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/rejected-new.png','00000000-0000-0000-0000-0000000009c2')$$,'42501',null,'E09 upload denied when the evidence row is rejected');
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/no-row.png','00000000-0000-0000-0000-0000000009c2')$$,'42501',null,'E10 upload denied when no evidence row exists for the key');
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9b000000-0000-0000-0000-00000000000b/93000000-0000-0000-0000-0000000000b1/wrongpath.png','00000000-0000-0000-0000-0000000009c2')$$,'42501',null,'E11 upload denied when the key path names another tenant than the evidence row');
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('other-bucket','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-new.png','00000000-0000-0000-0000-0000000009c2')$$,'42501',null,'E12 upload denied outside the evidence bucket');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c4',true);
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/pending-new.png','00000000-0000-0000-0000-0000000009c4')$$,'42501',null,'E13 tenant B cannot upload to a tenant A pending key');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c3',true);
select extensions.throws_ok($$insert into storage.objects(bucket_id,name,owner) values('sentriq-hse-evidence','9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/reader-own.png','00000000-0000-0000-0000-0000000009c3')$$,'42501',null,'E14 reader without upload permission cannot upload even for its own pending row');
do $$ declare n integer; begin
  update storage.objects set name=name||'x' where bucket_id='sentriq-hse-evidence';
  get diagnostics n = row_count; perform set_config('iso.e15', n::text, true);
exception when others then perform set_config('iso.e15', 'error ' || sqlstate, true); end $$;
select extensions.is(current_setting('iso.e15'),'0','E15 no UPDATE policy: a user cannot rename any evidence object (0 rows touched, no error)');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c2',true);
with d as (delete from storage.objects where bucket_id='sentriq-hse-evidence' and name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png' returning 1) select extensions.is((select count(*)::int from d),0,'E18 uploader cannot delete a confirmed object (no DELETE policy, RLS hides the row)');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009c3',true);
with d as (delete from storage.objects where bucket_id='sentriq-hse-evidence' returning 1) select extensions.is((select count(*)::int from d),0,'E19 reader with hse.evidence.read cannot delete any evidence object');
reset role;
set local role anon;
select extensions.throws_ok($$select count(*) from storage.objects$$,'42501',null,'E16 anon has no access to storage.objects');
reset role;
select extensions.is((select count(*)::int from storage.objects where bucket_id='sentriq-hse-evidence' and name='9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/confirmed.png'),1,'E20 the confirmed object is still there after the delete attempts');
select extensions.is((select count(*)::int from storage.objects where bucket_id='sentriq-hse-evidence' and name like '%x'),0,'E21 E15 post-check: no evidence object name was changed by the rename attempt');
select extensions.is((select count(*)::int from storage.objects where name like '9a000000-0000-0000-0000-00000000000a/93000000-0000-0000-0000-0000000000a1/%'),3,'E17 after all attempts only the permitted upload was added (2 fixture objects + 1)');
select * from extensions.finish();
rollback;
