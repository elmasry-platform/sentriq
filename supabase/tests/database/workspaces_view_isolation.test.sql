-- Cross-tenant isolation for HSE records, billing tables and the audit log, plus audit immutability.
-- Fixture: tenant A and tenant B both have the hse module and one employee with the same tenant-wide read role
-- (inspections, findings, actions, evidence, forms, audit) and write on findings. Data exists only in tenant A.
-- Tenant A's reader proves the policies let a legitimate reader through; tenant B's reader must still see nothing.
-- Billing tables (core.invoices, core.payments) are readable by platform operators only, so tenant readers see 0 by design.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(12);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000009a1','authenticated','authenticated','iso-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a2','authenticated','authenticated','iso-reader-a@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a3','authenticated','authenticated','iso-reader-b@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000009a4','authenticated','authenticated','iso-admin-a@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000009a1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values ('9a000000-0000-0000-0000-00000000000a','Isolation A','00000000-0000-0000-0000-0000000009a1'),('9b000000-0000-0000-0000-00000000000b','Isolation B','00000000-0000-0000-0000-0000000009a1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('91000000-0000-0000-0000-000000000001','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009a2','employee','active','iso-reader-a@example.test'),
 ('91000000-0000-0000-0000-000000000002','9b000000-0000-0000-0000-00000000000b','00000000-0000-0000-0000-0000000009a3','employee','active','iso-reader-b@example.test'),
 ('91000000-0000-0000-0000-000000000003','9a000000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000009a4','company_superadmin','active','iso-admin-a@example.test');
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

-- api.v_workspaces (security_invoker view over core.tenants): each member sees only their own workspace.
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a2',true);
select extensions.is((select count(*)::int from api.v_workspaces where id='9a000000-0000-0000-0000-00000000000a'),1,'V01 positive control: a tenant A member sees workspace A');
select extensions.is((select count(*)::int from api.v_workspaces),1,'V02 a tenant A member sees exactly one workspace row in total');
select extensions.is((select count(*)::int from api.v_workspaces where id<>'9a000000-0000-0000-0000-00000000000a' or "workspaceId"<>'9a000000-0000-0000-0000-00000000000a'),0,'V03 a tenant A member sees no other workspace (B or any other)');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a3',true);
select extensions.is((select string_agg(id::text,',') from api.v_workspaces),'9b000000-0000-0000-0000-00000000000b','V04 symmetry: a tenant B member sees only workspace B');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009ff',true);
select extensions.is((select count(*)::int from api.v_workspaces),0,'V05 a signed-in user with no membership sees no workspace');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a1',true);
select extensions.is((select count(*)::int from api.v_workspaces),0,'V06 documented: a platform operator reads no workspace through this view (restrictive boundary policy)');
reset role;
set local role anon;
select extensions.throws_ok($$select count(*) from api.v_workspaces$$,'42501',null,'V07 anon is denied on api.v_workspaces');
reset role;
select extensions.ok((select coalesce('security_invoker=true'=any(c.reloptions),false) from pg_class c where c.oid='api.v_workspaces'::regclass),'V08 the view runs as the caller (security_invoker), so core.tenants RLS applies');
select extensions.ok(has_table_privilege('authenticated','api.v_workspaces','select') and not has_table_privilege('anon','api.v_workspaces','select'),'V09 grants: authenticated can select, anon cannot');
-- Status filters live in the RLS function (active tenant AND active membership), not in the view.
insert into core.tenants(id,name,created_by) values ('9c000000-0000-0000-0000-00000000000c','Workspace C','00000000-0000-0000-0000-0000000009a1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values ('92000000-0000-0000-0000-0000000009c1','9c000000-0000-0000-0000-00000000000c','00000000-0000-0000-0000-0000000009a2','employee','active','iso-reader-a@example.test');
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000009a2',true);
select extensions.is((select count(*)::int from api.v_workspaces where id in ('9a000000-0000-0000-0000-00000000000a','9c000000-0000-0000-0000-00000000000c')),2,'V10 positive control: a user with two active memberships in two active companies sees both');
reset role;
update core.tenants set status='suspended' where id='9c000000-0000-0000-0000-00000000000c';
set local role authenticated;
select extensions.is((select count(*)::int from api.v_workspaces where id='9c000000-0000-0000-0000-00000000000c'),0,'V11 a suspended company is not visible through the view, even to its active member');
reset role;
update iam.memberships set status='suspended' where id='92000000-0000-0000-0000-0000000009c1' or (tenant_id='9a000000-0000-0000-0000-00000000000a' and user_id='00000000-0000-0000-0000-0000000009a2');
set local role authenticated;
select extensions.is((select count(*)::int from api.v_workspaces),0,'V12 a member whose membership is suspended sees no workspace');
reset role;
select * from extensions.finish();
rollback;
