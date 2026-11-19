$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$migrations = Get-ChildItem (Join-Path $root 'supabase/migrations') -Filter '*.sql' | Sort-Object Name
$sql = (($migrations | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n").ToLowerInvariant()
$forwardMigrations = @($migrations | Where-Object { $_.Name -ne '202611190001_sentriq_hse.sql' })
$forwardSql = (($forwardMigrations | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n").ToLowerInvariant()
$required = @(
  'core.features', 'core.plans', 'core.plan_entitlements', 'core.subscriptions',
  'core.subscription_items', 'core.entitlement_grants', 'core.usage_events', 'core.invoices',
  'core.invoice_items', 'core.payments', 'iam.roles', 'iam.role_permissions',
  'iam.membership_roles', 'iam.org_unit_access', 'iam.invitations',
  'private.has_feature_entitlement', 'private.has_module_entitlement', 'api.record_feature_usage', 'api.invoice_usage_event',
  'g.status=''active''', 'iam.membership_role_sites', 'iam.membership_role_org_units',
  'drop policy org_write on core.org_units', 'drop policy membership_write on iam.memberships',
  'drop policy followups_write on hse.follow_ups',
  'drop policy entitlements_insert on core.tenant_entitlements', 'drop policy entitlements_update on core.tenant_entitlements',
  'create policy plans_read on core.plans for select to authenticated using(private.is_platform_operator())',
  'create policy plan_entitlements_read on core.plan_entitlements for select to authenticated using(private.is_platform_operator())',
  'private.audit_row_change', 'private.guard_audit_immutable'
)
$missing = @($required | Where-Object { $sql -notmatch [regex]::Escape($_) })
if ($missing.Count -gt 0) { throw "Missing required contract markers: $($missing -join ', ')" }
foreach ($unsafe in @(
  'grant execute on function api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb) to authenticated',
  'grant execute on function private.has_module_entitlement(uuid,text) to authenticated',
  'grant execute on function private.has_hse_permission(uuid,uuid,text,uuid,boolean,text,uuid) to authenticated'
)) {
  if ($sql.Contains($unsafe)) { throw "Unsafe or legacy path found: $unsafe" }
}
if ($forwardSql -match '(?is)create\s+policy\s+(org_write|membership_write|followups_write)\s+on\b[^;]+?\bfor\s+all\b') {
  throw 'A forward migration reintroduced a broad FOR ALL write policy.'
}
$tenantFunction = [regex]::Match($forwardSql, '(?is)create\s+or\s+replace\s+function\s+api\.create_tenant\([^)]*\).*?as\s+\$\$(.*?)\$\$;')
if (-not $tenantFunction.Success -or $tenantFunction.Groups[1].Value -match '(?is)insert\s+into\s+core\.tenant_entitlements') {
  throw 'The forward tenant-provisioning function is missing or still grants a legacy module entitlement.'
}
if ($sql -notmatch 'grant execute on function api\.record_feature_usage\(uuid,uuid,text,text,numeric,text,jsonb\) to service_role') {
  throw 'The usage recorder is not granted to service_role.'
}
$test = Get-Content -Raw (Join-Path $root 'supabase/tests/database/entitlements_rbac.test.sql')
$planMatch = [regex]::Match($test, 'extensions\.plan\((\d+)\)')
$assertionCount = [regex]::Matches($test, 'extensions\.(ok|is|throws_ok|lives_ok|throws_like|cmp_ok|results_eq|set_eq)\(').Count
if (-not $planMatch.Success -or [int]$planMatch.Groups[1].Value -ne $assertionCount) {
  throw "pgTAP plan/count mismatch: plan=$($planMatch.Groups[1].Value), assertions=$assertionCount"
}
Write-Output "PASS: $($required.Count) static contract markers, legacy FOR ALL policies are dropped and not reintroduced, service_role-only usage recording, and $assertionCount synchronized pgTAP assertions."
