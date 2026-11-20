$ErrorActionPreference = 'Stop'

$container = @(& docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'supabase_db_sentriq' }) | Select-Object -First 1
if (-not $container) { throw 'The disposable local Supabase database container supabase_db_sentriq is not running.' }

$tenantA = [guid]::NewGuid().ToString('D')
$tenantB = [guid]::NewGuid().ToString('D')
$superA = [guid]::NewGuid().ToString('D')
$superB = [guid]::NewGuid().ToString('D')
$platformOwner = [guid]::NewGuid().ToString('D')
$uninvitedUser = [guid]::NewGuid().ToString('D')
$invitedUser = [guid]::NewGuid().ToString('D')
$superAMembership = [guid]::NewGuid().ToString('D')
$invitedMembership = [guid]::NewGuid().ToString('D')
$superBMembership = [guid]::NewGuid().ToString('D')
$siteA = [guid]::NewGuid().ToString('D')
$siteB = [guid]::NewGuid().ToString('D')
$templateB = [guid]::NewGuid().ToString('D')
$versionB = [guid]::NewGuid().ToString('D')
$inspectionB = [guid]::NewGuid().ToString('D')
$findingB = [guid]::NewGuid().ToString('D')
$actionB = [guid]::NewGuid().ToString('D')
$updateB = [guid]::NewGuid().ToString('D')
$followUpB = [guid]::NewGuid().ToString('D')
$evidenceB = [guid]::NewGuid().ToString('D')
$evidenceKeyB = "$tenantB/$siteB/audit-evidence.txt"
$uninvitedEmail = "uninvited-$([guid]::NewGuid().ToString('N'))@example.test"
$invitedEmail = "invited-$([guid]::NewGuid().ToString('N'))@example.test"

$sql = @"
begin;
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$superA','authenticated','authenticated','super-a-$([guid]::NewGuid().ToString('N'))@example.test','',now(),'{}','{}',now(),now());
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$superB','authenticated','authenticated','super-b-$([guid]::NewGuid().ToString('N'))@example.test','',now(),'{}','{}',now(),now());
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$platformOwner','authenticated','authenticated','platform-owner-$([guid]::NewGuid().ToString('N'))@example.test','',now(),'{}','{}',now(),now());
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$uninvitedUser','authenticated','authenticated','$uninvitedEmail','',now(),'{}','{}',now(),now());
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$invitedUser','authenticated','authenticated','$invitedEmail','',now(),'{}','{}',now(),now());
insert into core.tenants(id,name,created_by) values('$tenantA','Audit Tenant A','$superA'),('$tenantB','Audit Tenant B','$superB');
insert into iam.platform_operators(user_id,operator_role) values('$platformOwner','owner');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email)
values('$superAMembership','$tenantA','$superA','company_superadmin','active','super-a@example.test'),
      ('$superBMembership','$tenantB','$superB','company_superadmin','active','super-b@example.test');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email)
values('$invitedMembership','$tenantA','$invitedUser','employee','invited','$invitedEmail');
insert into core.sites(id,tenant_id,name,code) values('$siteA','$tenantA','Site A','AUD-A'),('$siteB','$tenantB','Site B','AUD-B');
set local request.jwt.claim.sub='$superB';
insert into hse.form_templates(id,tenant_id,title,category,owner_membership_id,created_by)
values('$templateB','$tenantB','{"en":"Audit form"}'::jsonb,'audit','$superBMembership','$superB');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by)
values('$versionB','$tenantB','$templateB',1,'{}'::jsonb,'$superB');
insert into hse.inspections(id,tenant_id,site_id,template_id,form_version_id,title,inspector_membership_id)
values('$inspectionB','$tenantB','$siteB','$templateB','$versionB','Audit inspection','$superBMembership');
insert into hse.findings(id,tenant_id,site_id,inspection_id,title,created_by)
values('$findingB','$tenantB','$siteB','$inspectionB','Audit finding','$superB');
insert into hse.corrective_actions(id,tenant_id,site_id,finding_id,inspection_id,title,owner_membership_id,created_by)
values('$actionB','$tenantB','$siteB','$findingB','$inspectionB','Audit action','$superBMembership','$superB');
insert into hse.action_updates(id,tenant_id,action_id,actor_membership_id,actor_user_id,status)
values('$updateB','$tenantB','$actionB','$superBMembership','$superB','open');
insert into hse.follow_ups(id,tenant_id,action_id,title,owner_membership_id,due_at)
values('$followUpB','$tenantB','$actionB','Audit follow-up','$superBMembership',now()+interval '1 day');
insert into hse.evidence_files(id,tenant_id,site_id,linked_record_type,linked_record_id,storage_key,file_name,mime_type,size_bytes,uploaded_by,status)
values('$evidenceB','$tenantB','$siteB','finding','$findingB','$evidenceKeyB','audit-evidence.txt','text/plain',12,'$superB','confirmed');
insert into storage.objects(bucket_id,name,metadata)
values('sentriq-hse-evidence','$evidenceKeyB','{"mimetype":"text/plain"}'::jsonb);

set local request.jwt.claim.sub='$platformOwner';
set local role authenticated;
do `$`$ begin
  perform api.issue_entitlement_grant('$tenantA','hse',null,'$superAMembership',now(),now()+interval '1 day','Audit membership module grant','complimentary',null,null,null);
  raise exception 'AUDIT_PROBE_UNEXPECTED_MEMBER_MODULE_GRANT_SUCCEEDED';
exception when sqlstate '22023' then
  raise notice 'MEMBERSHIP_MODULE_GRANT=blocked';
end `$`$;
reset role;
set local request.jwt.claim.sub='$superA';
set local role authenticated;
do `$`$ begin
  perform api.manage_subowner('$invitedUser',true);
  raise exception 'AUDIT_PROBE_UNEXPECTED_COMPANY_SUBOWNER_MANAGEMENT_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'COMPANY_SUPERADMIN_SUBOWNER_RPC=blocked';
end `$`$;
do `$`$ begin
  insert into iam.platform_operators(user_id,operator_role) values('$invitedUser','subowner');
  raise exception 'AUDIT_PROBE_UNEXPECTED_COMPANY_OPERATOR_INSERT_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'COMPANY_SUPERADMIN_OPERATOR_INSERT=blocked';
end `$`$;
select 'TENANT_A_HSE_MODULE_ENTITLEMENT='||(select entitled from api.list_my_entitlements('$tenantA') where entitlement_kind='module' and entitlement_key='hse');
select 'TENANT_B_SELECT='||(select count(*) from core.tenants where id='$tenantB');
select 'SITE_B_SELECT='||(select count(*) from core.sites where id='$siteB');
select 'SITE_VIEW_B_SELECT='||(select count(*) from api.v_sites where id='$siteB');
select 'INSPECTION_B_SELECT='||(select count(*) from hse.inspections where id='$inspectionB');
select 'FINDING_B_SELECT='||(select count(*) from hse.findings where id='$findingB');
select 'ACTION_B_SELECT='||(select count(*) from hse.corrective_actions where id='$actionB');
select 'ACTION_UPDATE_B_SELECT='||(select count(*) from hse.action_updates where id='$updateB');
select 'FOLLOW_UP_B_SELECT='||(select count(*) from hse.follow_ups where id='$followUpB');
select 'EVIDENCE_METADATA_B_SELECT='||(select count(*) from hse.evidence_files where id='$evidenceB');
select 'STORAGE_OBJECT_B_SELECT='||(select count(*) from storage.objects where bucket_id='sentriq-hse-evidence' and name='$evidenceKeyB');
with changed as (update core.sites set name='Unauthorized change' where id='$siteB' returning id)
select 'SITE_B_UPDATE_ROWS='||(select count(*) from changed);
do `$`$ begin
  insert into core.sites(tenant_id,name,code) values('$tenantB','Forged Site','AUD-X');
  raise exception 'AUDIT_PROBE_UNEXPECTED_CROSS_TENANT_INSERT_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'CROSS_TENANT_SITE_INSERT=blocked';
end `$`$;
do `$`$ begin
  delete from core.sites where id='$siteB';
  raise exception 'AUDIT_PROBE_UNEXPECTED_CROSS_TENANT_DELETE_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'CROSS_TENANT_SITE_DELETE=blocked';
end `$`$;
do `$`$ begin
  insert into iam.memberships(tenant_id,user_id,member_role,status,email)
  values('$tenantA','$uninvitedUser','employee','active','$uninvitedEmail');
  raise exception 'AUDIT_PROBE_UNEXPECTED_MEMBERSHIP_INSERT_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'DIRECT_MEMBERSHIP_INSERT=blocked';
end `$`$;
do `$`$ begin
  update iam.memberships set status='active' where tenant_id='$tenantA' and id='$invitedMembership';
  raise exception 'AUDIT_PROBE_UNEXPECTED_INVITATION_ACTIVATION_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'DIRECT_INVITATION_BYPASS_ACTIVATION=blocked';
end `$`$;
do `$`$ begin
  update iam.memberships set email='forged@example.test' where tenant_id='$tenantB' and id='$superBMembership';
  raise exception 'AUDIT_PROBE_UNEXPECTED_CROSS_TENANT_MEMBERSHIP_UPDATE_SUCCEEDED';
exception when insufficient_privilege then
  raise notice 'CROSS_TENANT_MEMBERSHIP_UPDATE=blocked';
end `$`$;
set local request.jwt.claim.sub='$uninvitedUser';
select 'UNINVITED_USER_TENANT_ACCESS='||(select count(*) from core.tenants where id='$tenantA');
reset role;
rollback;
"@

$output = $sql | & docker exec -i $container psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
$exitCode = $LASTEXITCODE
$outputText = $output -join "`n"
if ($exitCode -ne 0) { throw "Security review probes failed to execute: $outputText" }

foreach ($expected in @(
  'TENANT_B_SELECT=0',
  'SITE_B_SELECT=0',
  'SITE_VIEW_B_SELECT=0',
  'INSPECTION_B_SELECT=0',
  'FINDING_B_SELECT=0',
  'ACTION_B_SELECT=0',
  'ACTION_UPDATE_B_SELECT=0',
  'FOLLOW_UP_B_SELECT=0',
  'EVIDENCE_METADATA_B_SELECT=0',
  'STORAGE_OBJECT_B_SELECT=0',
  'SITE_B_UPDATE_ROWS=0',
  'CROSS_TENANT_SITE_INSERT=blocked',
  'CROSS_TENANT_SITE_DELETE=blocked',
  'COMPANY_SUPERADMIN_SUBOWNER_RPC=blocked',
  'COMPANY_SUPERADMIN_OPERATOR_INSERT=blocked',
  'MEMBERSHIP_MODULE_GRANT=blocked',
  'DIRECT_MEMBERSHIP_INSERT=blocked',
  'DIRECT_INVITATION_BYPASS_ACTIVATION=blocked',
  'CROSS_TENANT_MEMBERSHIP_UPDATE=blocked',
  'UNINVITED_USER_TENANT_ACCESS=0'
)) {
  if ($outputText -notmatch [regex]::Escape($expected)) { throw "Expected probe evidence missing: $expected. Output: $outputText" }
}

Write-Output 'PASS: authenticated Company Superadmin cannot cross-read Company B sites, HSE child records, evidence metadata, storage objects, or invoker views; cannot cross-update/insert/delete sites or update cross-tenant membership; direct membership insert/activation is denied; member-scoped module grants are rejected; uninvited identity has no tenant access.'
