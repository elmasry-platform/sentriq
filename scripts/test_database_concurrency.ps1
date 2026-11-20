param([switch]$InjectFailureAfterSetup)

$ErrorActionPreference = 'Stop'

$container = @(& docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'supabase_db_sentriq' }) | Select-Object -First 1
if (-not $container) { throw 'The disposable local Supabase database container supabase_db_sentriq is not running.' }

function Invoke-LocalDatabaseSql([string]$Sql) {
  $captured = $Sql | & docker exec -i $container psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
  $code = $LASTEXITCODE
  [pscustomobject]@{ ExitCode = $code; Output = ($captured -join "`n") }
}

function Invoke-ServiceRoleSql([string]$Sql) {
  $wrapped = @"
begin;
select set_config('request.headers','{"x-request-id":"$runId"}',true);
select set_config('request.jwt.claim.role','service_role',true);
select set_config('request.jwt.claim.sub','$userId',true);
set local role service_role;
select current_user;
$Sql
commit;
"@
  Invoke-LocalDatabaseSql $wrapped
}

$runId = 'sentriq-f03-' + [guid]::NewGuid().ToString('N')
$tenantId = [guid]::NewGuid().ToString('D')
$userId = [guid]::NewGuid().ToString('D')
$membershipId = [guid]::NewGuid().ToString('D')
$moduleGrantId = [guid]::NewGuid().ToString('D')
$featureGrantId = [guid]::NewGuid().ToString('D')
$invitedUserId = [guid]::NewGuid().ToString('D')
$invitedMembershipId = [guid]::NewGuid().ToString('D')
$invitationId = [guid]::NewGuid().ToString('D')
$email = "concurrency-$([guid]::NewGuid().ToString('N'))@example.test"
$inviteEmail = "invite-$([guid]::NewGuid().ToString('N'))@example.test"
$token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$quota = 3
$requestCount = 12
$jobs = [System.Collections.Generic.List[object]]::new()
$primaryFailure = $null
$invoiceId = [guid]::NewGuid().ToString('D')

$setup = @"
begin;
select set_config('request.headers','{"x-request-id":"$runId"}',true);
select set_config('request.jwt.claim.sub','$userId',true);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$userId','authenticated','authenticated','$email','',now(),'{}','{}',now(),now());
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$invitedUserId','authenticated','authenticated','$inviteEmail','',now(),'{}','{}',now(),now());
insert into core.tenants(id,name,created_by) values('$tenantId','Synthetic concurrency $runId','$userId');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email)
values('$membershipId','$tenantId','$userId','employee','active','$email'),
      ('$invitedMembershipId','$tenantId','$invitedUserId','employee','invited','$inviteEmail');
insert into core.entitlement_grants(id,tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
values('$moduleGrantId','$tenantId','hse',now()-interval '1 minute',now()+interval '1 day','$userId','Synthetic concurrency module grant','complimentary');
insert into core.entitlement_grants(id,tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment,bill_to_tenant_id,currency,unit_price_minor,quota)
values('$featureGrantId','$tenantId','hse.copilot','$membershipId',now()-interval '1 minute',now()+interval '1 day','$userId','Synthetic concurrency quota grant','tenant_billable','$tenantId','USD',7,$quota);
insert into iam.invitations(id,tenant_id,email,token_hash,intended_level,invited_by,expires_at)
values('$invitationId','$tenantId','$inviteEmail',extensions.digest('$token','sha256'),'employee','$userId',now()+interval '1 day');
commit;
"@

try {
  $setupResult = Invoke-LocalDatabaseSql $setup
  if ($setupResult.ExitCode -ne 0) { throw "Could not prepare synthetic concurrency fixtures: $($setupResult.Output)" }
  if ($InjectFailureAfterSetup) { throw 'Intentional F-03 failure injection after fixture setup.' }

  $requestKeys = @()
  $usageJobs = @()
  for ($i = 0; $i -lt $requestCount; $i++) {
    $key = [guid]::NewGuid().ToString('N')
    $requestKeys += $key
    $sql = @"
select pg_sleep(0.2);
select api.record_feature_usage('$tenantId','$membershipId','hse.copilot','$key',1,'request','{}'::jsonb);
"@
    $job = Start-Job -ArgumentList $sql,$container,$runId,$userId,$key -ScriptBlock {
      param($Query,$DatabaseContainer,$RequestId,$SubjectId,$RequestKey)
      $ErrorActionPreference = 'Continue'
      $wrapped = @"
begin;
select set_config('request.headers','{"x-request-id":"$RequestId"}',true);
select set_config('request.jwt.claim.role','service_role',true);
select set_config('request.jwt.claim.sub','$SubjectId',true);
set local role service_role;
select current_user;
$Query
commit;
"@
      $captured = $wrapped | & docker exec -i $DatabaseContainer psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
      [pscustomobject]@{ RequestKey = $RequestKey; ExitCode = $LASTEXITCODE; Output = ($captured -join "`n") }
    }
    $usageJobs += $job
    $jobs.Add($job)
  }
  $null = Wait-Job -Job $usageJobs
  $usageResults = @($usageJobs | Receive-Job)
  foreach ($job in $usageJobs) { $null = $jobs.Remove($job); Remove-Job -Job $job -Force }
  $usageSuccess = @($usageResults | Where-Object { $_.ExitCode -eq 0 })
  $usageDenied = @($usageResults | Where-Object { $_.ExitCode -ne 0 })
  if ($usageSuccess.Count -ne $quota) {
    throw "Concurrent quota test expected $quota successful service_role calls, received $($usageSuccess.Count). Results: $($usageResults | ConvertTo-Json -Compress)"
  }
  if ($usageDenied.Count -ne ($requestCount - $quota) -or @($usageDenied | Where-Object { $_.Output -notmatch 'grant_usage_quota_exceeded' }).Count -gt 0) {
    throw "Concurrent quota test saw unexpected failures. Results: $($usageResults | ConvertTo-Json -Compress)"
  }
  $usageCheck = Invoke-LocalDatabaseSql "select count(*)||'|'||coalesce(sum(quantity),0) from core.usage_events where tenant_id='$tenantId' and grant_id='$featureGrantId';"
  if ($usageCheck.ExitCode -ne 0 -or $usageCheck.Output.Trim() -ne '3|3.000000') {
    throw "Concurrent quota was exceeded or usage rows were duplicated: $($usageCheck.Output)"
  }

  $successfulKey = $usageSuccess[0].RequestKey
  $firstEvent = Invoke-LocalDatabaseSql "select id from core.usage_events where tenant_id='$tenantId' and grant_id='$featureGrantId' and idempotency_key='$successfulKey';"
  if ($firstEvent.ExitCode -ne 0 -or $firstEvent.Output.Trim() -notmatch '^[0-9a-f-]{36}$') { throw "Could not select the successful usage event: $($firstEvent.Output)" }
  $usageEventId = $firstEvent.Output.Trim()
  $retry = Invoke-ServiceRoleSql "select api.record_feature_usage('$tenantId','$membershipId','hse.copilot','$successfulKey',1,'request','{}'::jsonb);"
  if ($retry.ExitCode -ne 0 -or $retry.Output -notmatch [regex]::Escape($usageEventId) -or $retry.Output -notmatch 'service_role') {
    throw "Exact retry after quota exhaustion did not return the original event under service_role: $($retry.Output)"
  }
  $conflict = Invoke-ServiceRoleSql "select api.record_feature_usage('$tenantId','$membershipId','hse.copilot','$successfulKey',2,'request','{}'::jsonb);"
  if ($conflict.ExitCode -eq 0 -or $conflict.Output -notmatch 'idempotency_key_payload_conflict') {
    throw "Conflicting idempotency payload was not deterministically rejected: $($conflict.Output)"
  }

  $invoiceNumber = "CONCURRENT-$([guid]::NewGuid().ToString('N'))"
  $invoiceCreate = Invoke-ServiceRoleSql "select api.create_invoice_draft('$tenantId','$invoiceNumber','USD',now()-interval '1 day',now()+interval '1 day');"
  if ($invoiceCreate.ExitCode -ne 0) { throw "Could not create the synthetic draft invoice under service_role: $($invoiceCreate.Output)" }
  $invoiceIds = [regex]::Matches($invoiceCreate.Output,'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($invoiceIds.Count -eq 0) { throw "Invoice draft RPC did not return an ID: $($invoiceCreate.Output)" }
  $invoiceId = $invoiceIds[$invoiceIds.Count - 1].Value

  $invoiceJobs = @()
  for ($i = 0; $i -lt 8; $i++) {
    $sql = @"
select pg_sleep(0.1);
select api.invoice_usage_event('$usageEventId','$invoiceId','Synthetic concurrent usage line');
"@
    $job = Start-Job -ArgumentList $sql,$container,$runId,$userId -ScriptBlock {
      param($Query,$DatabaseContainer,$RequestId,$SubjectId)
      $ErrorActionPreference = 'Continue'
      $wrapped = @"
begin;
select set_config('request.headers','{"x-request-id":"$RequestId"}',true);
select set_config('request.jwt.claim.role','service_role',true);
select set_config('request.jwt.claim.sub','$SubjectId',true);
set local role service_role;
select current_user;
$Query
commit;
"@
      $captured = $wrapped | & docker exec -i $DatabaseContainer psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
      [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($captured -join "`n") }
    }
    $invoiceJobs += $job
    $jobs.Add($job)
  }
  $null = Wait-Job -Job $invoiceJobs
  $invoiceResults = @($invoiceJobs | Receive-Job)
  foreach ($job in $invoiceJobs) { $null = $jobs.Remove($job); Remove-Job -Job $job -Force }
  if (@($invoiceResults | Where-Object { $_.ExitCode -eq 0 -and $_.Output -match 'service_role' }).Count -ne 8) {
    throw "Concurrent invoice retries did not all execute as service_role: $($invoiceResults | ConvertTo-Json -Compress)"
  }
  $invoiceCheck = Invoke-LocalDatabaseSql "select (select count(*) from core.invoice_items where tenant_id='$tenantId' and invoice_id='$invoiceId' and usage_event_id='$usageEventId')||'|'||(select subtotal_minor||'|'||total_minor from core.invoices where tenant_id='$tenantId' and id='$invoiceId');"
  if ($invoiceCheck.ExitCode -ne 0 -or $invoiceCheck.Output.Trim() -ne '1|7|7') {
    throw "Concurrent invoice calls duplicated a line or incremented totals more than once: $($invoiceCheck.Output)"
  }

  $inviteJobs = @()
  for ($i = 0; $i -lt 2; $i++) {
    $sql = "select api.accept_invitation('$token','$invitedUserId');"
    $job = Start-Job -ArgumentList $sql,$container,$runId,$userId -ScriptBlock {
      param($Query,$DatabaseContainer,$RequestId,$SubjectId)
      $ErrorActionPreference = 'Continue'
      $wrapped = @"
begin;
select set_config('request.headers','{"x-request-id":"$RequestId"}',true);
select set_config('request.jwt.claim.role','service_role',true);
select set_config('request.jwt.claim.sub','$SubjectId',true);
set local role service_role;
select current_user;
$Query
commit;
"@
      $captured = $wrapped | & docker exec -i $DatabaseContainer psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
      [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($captured -join "`n") }
    }
    $inviteJobs += $job
    $jobs.Add($job)
  }
  $null = Wait-Job -Job $inviteJobs
  $inviteResults = @($inviteJobs | Receive-Job)
  foreach ($job in $inviteJobs) { $null = $jobs.Remove($job); Remove-Job -Job $job -Force }
  $inviteSuccess = @($inviteResults | Where-Object { $_.ExitCode -eq 0 -and $_.Output -match 'service_role' })
  $inviteDenied = @($inviteResults | Where-Object { $_.ExitCode -ne 0 -and $_.Output -match 'invitation_invalid_or_expired' })
  if ($inviteSuccess.Count -ne 1 -or $inviteDenied.Count -ne 1) {
    throw "Concurrent invitation acceptance did not produce one accepted and one rejected service_role call: $($inviteResults | ConvertTo-Json -Compress)"
  }
  $inviteCheck = Invoke-LocalDatabaseSql "select (select count(*) from iam.memberships where tenant_id='$tenantId' and id='$invitedMembershipId' and status='active')||'|'||(select count(*) from iam.invitations where tenant_id='$tenantId' and id='$invitationId' and accepted_at is not null);"
  if ($inviteCheck.ExitCode -ne 0 -or $inviteCheck.Output.Trim() -ne '1|1') {
    throw "Concurrent invite acceptance changed membership or invitation state unexpectedly: $($inviteCheck.Output)"
  }

  Write-Output "PASS: $requestCount actual service_role SQL sessions respected quota=$quota; exact exhausted-quota retry and conflicting payload were checked; eight service_role invoice retries created one line and updated totals once; concurrent invitation acceptance succeeded exactly once. Run marker: $runId"
}
catch {
  $primaryFailure = $_
}
finally {
  $runningJobs = @($jobs | Where-Object { $_.State -eq 'Running' })
  if ($runningJobs.Count -gt 0) { $runningJobs | Stop-Job -ErrorAction SilentlyContinue }
  if ($jobs.Count -gt 0) {
    $null = Wait-Job -Job @($jobs.ToArray()) -ErrorAction SilentlyContinue
    foreach ($job in @($jobs.ToArray())) {
      if ($job.State -ne 'Running') { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
  }

  $cleanup = @"
begin;
alter table audit.events disable trigger audit_events_immutable;
alter table core.usage_events disable trigger usage_events_immutable;
alter table core.invoice_items disable trigger invoice_items_immutable;
alter table core.tenants disable trigger audit_row_change;
alter table iam.memberships disable trigger audit_row_change;
alter table iam.invitations disable trigger audit_row_change;
alter table core.entitlement_grants disable trigger audit_row_change;
alter table core.usage_events disable trigger audit_row_change;
alter table core.invoices disable trigger audit_row_change;
alter table core.invoice_items disable trigger audit_row_change;
delete from audit.events
 where request_id='$runId'
    or (tenant_id='$tenantId' and action_key='iam.invitation.accepted'
        and record_type='iam.memberships' and record_id='$invitedMembershipId');
delete from core.invoice_items where tenant_id='$tenantId' and invoice_id='$invoiceId';
delete from core.invoices where tenant_id='$tenantId' and id='$invoiceId';
delete from core.usage_events where tenant_id='$tenantId' and grant_id='$featureGrantId';
delete from iam.invitations where tenant_id='$tenantId' and id='$invitationId';
delete from core.entitlement_grants where tenant_id='$tenantId' and id in ('$moduleGrantId','$featureGrantId');
delete from iam.memberships where tenant_id='$tenantId' and id in ('$membershipId','$invitedMembershipId');
delete from core.tenants where id='$tenantId';
delete from auth.users where id in ('$userId','$invitedUserId');
alter table audit.events enable trigger audit_events_immutable;
alter table core.usage_events enable trigger usage_events_immutable;
alter table core.invoice_items enable trigger invoice_items_immutable;
alter table core.tenants enable trigger audit_row_change;
alter table iam.memberships enable trigger audit_row_change;
alter table iam.invitations enable trigger audit_row_change;
alter table core.entitlement_grants enable trigger audit_row_change;
alter table core.usage_events enable trigger audit_row_change;
alter table core.invoices enable trigger audit_row_change;
alter table core.invoice_items enable trigger audit_row_change;
commit;
"@
  $cleanupResult = Invoke-LocalDatabaseSql $cleanup
  $verification = Invoke-LocalDatabaseSql @"
select
 (select count(*) from auth.users where id in ('$userId','$invitedUserId')) +
 (select count(*) from core.tenants where id='$tenantId') +
 (select count(*) from iam.memberships where tenant_id='$tenantId' and id in ('$membershipId','$invitedMembershipId')) +
 (select count(*) from iam.invitations where tenant_id='$tenantId' and id='$invitationId') +
 (select count(*) from core.entitlement_grants where tenant_id='$tenantId' and id in ('$moduleGrantId','$featureGrantId')) +
 (select count(*) from core.usage_events where tenant_id='$tenantId' and grant_id='$featureGrantId') +
 (select count(*) from core.invoices where tenant_id='$tenantId' and id='$invoiceId') +
 (select count(*) from core.invoice_items where tenant_id='$tenantId' and invoice_id='$invoiceId') +
 (select count(*) from audit.events where request_id='$runId'
   or (tenant_id='$tenantId' and action_key='iam.invitation.accepted'
       and record_type='iam.memberships' and record_id='$invitedMembershipId'));
"@
  if ($cleanupResult.ExitCode -ne 0 -or $verification.ExitCode -ne 0 -or $verification.Output.Trim() -ne '0') {
    $cleanupFailure = "F-03 cleanup verification failed for marker $runId. Cleanup: $($cleanupResult.Output) Verification: $($verification.Output)"
    if ($primaryFailure) { throw "$($primaryFailure.Exception.Message) $cleanupFailure" }
    throw $cleanupFailure
  }
  Write-Output "PASS: exact run $runId fixtures and audit rows were deleted in FK order; cleanup verification found zero synthetic rows."
}

if ($primaryFailure) { throw $primaryFailure }
