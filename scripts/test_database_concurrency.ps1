$ErrorActionPreference = 'Stop'

$container = @(& docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'supabase_db_sentriq' }) | Select-Object -First 1
if (-not $container) { throw 'The disposable local Supabase database container supabase_db_sentriq is not running.' }

function Invoke-LocalDatabaseSql([string]$Sql) {
  $output = $Sql | & docker exec -i $container psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
  $code = $LASTEXITCODE
  [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n") }
}

$tenantId = [guid]::NewGuid().ToString('D')
$userId = [guid]::NewGuid().ToString('D')
$membershipId = [guid]::NewGuid().ToString('D')
$moduleGrantId = [guid]::NewGuid().ToString('D')
$featureGrantId = [guid]::NewGuid().ToString('D')
$invitedUserId = [guid]::NewGuid().ToString('D')
$moduleGrantExpires = (Get-Date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-dd HH:mm:ss+00')
$featureGrantExpires = $moduleGrantExpires
$email = "concurrency-$([guid]::NewGuid().ToString('N'))@example.test"
$inviteEmail = "invite-$([guid]::NewGuid().ToString('N'))@example.test"
$token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$quota = 3
$requestCount = 12

$setup = @"
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$userId','authenticated','authenticated','$email','',now(),'{}','{}',now(),now());
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
values('$invitedUserId','authenticated','authenticated','$inviteEmail','',now(),'{}','{}',now(),now());
insert into core.tenants(id,name,created_by) values('$tenantId','Synthetic concurrency tenant','$userId');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email)
values('$membershipId','$tenantId','$userId','employee','active','$email');
insert into core.entitlement_grants(id,tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
values('$moduleGrantId','$tenantId','hse',now()-interval '1 minute','$moduleGrantExpires','$userId','Synthetic concurrency test module grant','complimentary');
insert into core.entitlement_grants(id,tenant_id,feature_key,membership_id,starts_at,expires_at,granted_by,reason,billing_treatment,bill_to_tenant_id,currency,unit_price_minor,quota)
values('$featureGrantId','$tenantId','hse.copilot','$membershipId',now()-interval '1 minute','$featureGrantExpires','$userId','Synthetic concurrency quota grant','tenant_billable','$tenantId','USD',7,$quota);
insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
values('$tenantId','$inviteEmail',extensions.digest('$token','sha256'),'employee','$userId',now()+interval '1 day');
"@
$setupResult = Invoke-LocalDatabaseSql $setup
if ($setupResult.ExitCode -ne 0) { throw "Could not prepare synthetic concurrency fixtures: $($setupResult.Output)" }

$jobs = @()
$requestKeys = @()
for ($i = 0; $i -lt $requestCount; $i++) {
  $key = [guid]::NewGuid().ToString('N')
  $requestKeys += $key
  $sql = @"
select set_config('request.jwt.claim.role','service_role',false);
select pg_sleep(0.2);
select api.record_feature_usage('$tenantId','$membershipId','hse.copilot','$key',1,'request','{}'::jsonb);
"@
  $jobs += Start-Job -ArgumentList $sql,$container,$key -ScriptBlock {
    param($Query,$DatabaseContainer,$RequestKey)
    $captured = $Query | & docker exec -i $DatabaseContainer psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
    [pscustomobject]@{ RequestKey = $RequestKey; ExitCode = $LASTEXITCODE; Output = ($captured -join "`n") }
  }
}
$null = Wait-Job -Job $jobs
$usageResults = @($jobs | Receive-Job)
$jobs | Remove-Job -Force
$usageSuccess = @($usageResults | Where-Object { $_.ExitCode -eq 0 })
$usageDenied = @($usageResults | Where-Object { $_.ExitCode -ne 0 })
if ($usageSuccess.Count -ne $quota) {
  throw "Concurrent quota test expected $quota successful calls, received $($usageSuccess.Count). Results: $($usageResults | ConvertTo-Json -Compress)"
}
if ($usageDenied.Count -ne ($requestCount - $quota) -or @($usageDenied | Where-Object { $_.Output -notmatch 'grant_usage_quota_exceeded' }).Count -gt 0) {
  throw "Concurrent quota test saw unexpected failures. Results: $($usageResults | ConvertTo-Json -Compress)"
}
$usageCheck = Invoke-LocalDatabaseSql "select count(*)||'|'||coalesce(sum(quantity),0) from core.usage_events where tenant_id='$tenantId' and grant_id='$featureGrantId';"
if ($usageCheck.ExitCode -ne 0 -or $usageCheck.Output.Trim() -ne '3|3.000000') {
  throw "Concurrent quota was exceeded or usage rows were duplicated: $($usageCheck.Output)"
}

$firstSuccess = $usageSuccess[0]
$eventIds = [regex]::Matches($firstSuccess.Output,'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
if ($eventIds.Count -eq 0) { throw "Successful usage request did not return an event ID: $($firstSuccess.Output)" }
$originalEventId = $eventIds[$eventIds.Count - 1].Value
$successfulKey = $firstSuccess.RequestKey
$retry = Invoke-LocalDatabaseSql "select set_config('request.jwt.claim.role','service_role',false); select api.record_feature_usage('$tenantId','$membershipId','hse.copilot','$successfulKey',1,'request','{}'::jsonb);"
if ($retry.ExitCode -ne 0 -or $retry.Output -notmatch [regex]::Escape($originalEventId)) {
  throw "Exact retry after quota exhaustion did not return the original event: $($retry.Output)"
}
$conflict = Invoke-LocalDatabaseSql "select set_config('request.jwt.claim.role','service_role',false); select api.record_feature_usage('$tenantId','$membershipId','hse.copilot','$successfulKey',2,'request','{}'::jsonb);"
if ($conflict.ExitCode -eq 0 -or $conflict.Output -notmatch 'idempotency_key_payload_conflict') {
  throw "Conflicting idempotency payload was not deterministically rejected: $($conflict.Output)"
}

$firstEvent = Invoke-LocalDatabaseSql "select id||'|'||idempotency_key from core.usage_events where tenant_id='$tenantId' and grant_id='$featureGrantId' order by occurred_at,id limit 1;"
if ($firstEvent.ExitCode -ne 0 -or $firstEvent.Output -notmatch '^([0-9a-f-]{36})\|([0-9a-f]{32})$') { throw "Could not select a successful usage event for invoice contention: $($firstEvent.Output)" }
$usageEventId = $Matches[1]
$invoiceRequestKey = $Matches[2]
$invoiceNumber = "CONCURRENT-$([guid]::NewGuid().ToString('N'))"
$invoiceSql = "select set_config('request.jwt.claim.role','service_role',false); select api.create_invoice_draft('$tenantId','$invoiceNumber','USD',now()-interval '1 day',now()+interval '1 day');"
$invoiceCreate = Invoke-LocalDatabaseSql $invoiceSql
if ($invoiceCreate.ExitCode -ne 0) { throw "Could not create the synthetic draft invoice: $($invoiceCreate.Output)" }
$invoiceIds = [regex]::Matches($invoiceCreate.Output,'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
if ($invoiceIds.Count -eq 0) { throw "Invoice draft RPC did not return an ID: $($invoiceCreate.Output)" }
$invoiceId = $invoiceIds[$invoiceIds.Count - 1].Value
$invoiceJobs = @()
for ($i = 0; $i -lt 8; $i++) {
  $sql = @"
select set_config('request.jwt.claim.role','service_role',false);
select pg_sleep(0.1);
select api.invoice_usage_event('$usageEventId','$invoiceId','Synthetic concurrent usage line');
"@
  $invoiceJobs += Start-Job -ArgumentList $sql,$container -ScriptBlock {
    param($Query,$DatabaseContainer)
    $captured = $Query | & docker exec -i $DatabaseContainer psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($captured -join "`n") }
  }
}
$null = Wait-Job -Job $invoiceJobs
$invoiceResults = @($invoiceJobs | Receive-Job)
$invoiceJobs | Remove-Job -Force
if (@($invoiceResults | Where-Object { $_.ExitCode -eq 0 }).Count -ne 8) {
  throw "Concurrent invoice retries were not idempotent: $($invoiceResults | ConvertTo-Json -Compress)"
}
$lineId = Invoke-LocalDatabaseSql "select id from core.invoice_items where usage_event_id='$usageEventId';"
if ($lineId.ExitCode -ne 0 -or $lineId.Output.Trim() -notmatch '^[0-9a-f-]{36}$') { throw "Concurrent invoice calls did not produce one line item: $($lineId.Output)" }
$invoiceCheck = Invoke-LocalDatabaseSql "select (select count(*) from core.invoice_items where usage_event_id='$usageEventId')||'|'||(select subtotal_minor||'|'||total_minor from core.invoices where id='$invoiceId');"
if ($invoiceCheck.ExitCode -ne 0 -or $invoiceCheck.Output.Trim() -ne '1|7|7') {
  throw "Concurrent invoice calls duplicated a line or incremented totals more than once: $($invoiceCheck.Output)"
}

$inviteJobs = @()
for ($i = 0; $i -lt 2; $i++) {
  $sql = @"
select set_config('request.jwt.claim.role','service_role',false);
select pg_sleep(0.1);
select api.accept_invitation('$token','$invitedUserId');
"@
  $inviteJobs += Start-Job -ArgumentList $sql,$container -ScriptBlock {
    param($Query,$DatabaseContainer)
    $captured = $Query | & docker exec -i $DatabaseContainer psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($captured -join "`n") }
  }
}
$null = Wait-Job -Job $inviteJobs
$inviteResults = @($inviteJobs | Receive-Job)
$inviteJobs | Remove-Job -Force
$inviteSuccess = @($inviteResults | Where-Object { $_.ExitCode -eq 0 })
$inviteDenied = @($inviteResults | Where-Object { $_.ExitCode -ne 0 })
if ($inviteSuccess.Count -ne 1 -or $inviteDenied.Count -ne 1 -or $inviteDenied[0].Output -notmatch 'invitation_invalid_or_expired') {
  throw "Concurrent invitation acceptance did not produce one accepted and one rejected request: $($inviteResults | ConvertTo-Json -Compress)"
}
$inviteCheck = Invoke-LocalDatabaseSql "select (select count(*) from iam.memberships where tenant_id='$tenantId' and user_id='$invitedUserId')||'|'||(select count(*) from iam.invitations where tenant_id='$tenantId' and email='$inviteEmail' and accepted_at is not null);"
if ($inviteCheck.ExitCode -ne 0 -or $inviteCheck.Output.Trim() -ne '1|1') {
  throw "Concurrent invite acceptance changed membership or invitation state unexpectedly: $($inviteCheck.Output)"
}

Write-Output "PASS: $requestCount concurrent usage requests respected quota=$quota; exact exhausted-quota retry and conflicting payload checked; 8 concurrent invoice retries created one line and incremented totals once; concurrent invitation acceptance succeeded exactly once."
