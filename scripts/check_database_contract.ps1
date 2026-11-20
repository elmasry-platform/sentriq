$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$migrations = Get-ChildItem (Join-Path $root 'supabase/migrations') -Filter '*.sql' | Sort-Object Name
$sql = (($migrations | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n").ToLowerInvariant()
$forwardMigrations = @($migrations | Where-Object { $_.Name -ne '202611190001_sentriq_hse.sql' })
$forwardSql = (($forwardMigrations | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n").ToLowerInvariant()
$remediationMigration = Join-Path $root 'supabase/migrations/202611200002_foundation_security_remediation.sql'
$remediationSql = (Get-Content -Raw $remediationMigration).ToLowerInvariant()
$required = @(
  'core.features', 'core.plans', 'core.plan_entitlements', 'core.subscriptions',
  'core.subscription_items', 'core.entitlement_grants', 'core.usage_events', 'core.invoices',
  'core.invoice_items', 'core.payments', 'iam.roles', 'iam.role_permissions',
  'iam.membership_roles', 'iam.org_unit_access', 'iam.invitations',
  'private.has_feature_entitlement', 'private.has_module_entitlement', 'api.record_feature_usage', 'api.invoice_usage_event',
  'usage_events_idempotency_key_global', 'private.guard_entitlement_grant_lifecycle',
  'membership_reactivation_access_reset', 'one_live_subscription_per_tenant',
  'api.set_entitlement_grant_status', 'api.manage_subowner(uuid,boolean)',
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
$remediationRequired = @(
  'drop policy if exists membership_insert on iam.memberships',
  'drop policy if exists membership_update on iam.memberships',
  'revoke all privileges on iam.memberships from anon, authenticated, service_role',
  'grant select on iam.memberships to authenticated',
  'api.set_membership_status',
  "p_status not in ('suspended','ended')",
  'entitlement_grants_module_tenant_scope',
  'module_grants_are_tenant_scoped',
  'alter default privileges for role postgres',
  'revoke execute on functions from public',
  'revoke execute on functions from public, anon, authenticated, service_role'
)
$missingRemediation = @($remediationRequired | Where-Object { $remediationSql -notmatch [regex]::Escape($_) })
if ($missingRemediation.Count -gt 0) { throw "Missing remediation migration markers: $($missingRemediation -join ', ')" }
if ($remediationSql -match 'create\s+table\s+if\s+not\s+exists|hse\.(incidents|risks|permits)') {
  throw 'The remediation migration contains hidden schema creation or future HSE domains.'
}
if ($migrations[-1].Name -ne '202611200002_foundation_security_remediation.sql') {
  throw 'The forward remediation migration is not the latest migration timestamp.'
}
$concurrencyHarness = Join-Path $root 'scripts/test_database_concurrency.ps1'
if (-not (Test-Path -LiteralPath $concurrencyHarness)) { throw 'The separate database concurrency harness is missing.' }
$concurrencySql = Get-Content -Raw $concurrencyHarness
if ($concurrencySql -notmatch '\[guid\]::NewGuid\(\)' -or $concurrencySql -notmatch '(?is)try\s*\{.*?finally\s*\{') {
  throw 'The concurrency harness must use unique IDs and guarantee cleanup in finally.'
}
if ($concurrencySql -notmatch 'Stop-Job' -or $concurrencySql -notmatch 'Wait-Job' -or $concurrencySql -notmatch 'cleanup verification found zero synthetic rows') {
  throw 'The concurrency harness must stop or wait for jobs and fail if exact fixtures remain.'
}
if ($concurrencySql -match '(?im)^\s*(truncate\s+|delete\s+from\s+\w+\.\w+\s*;|delete\s+from\s+\w+\.\w+\s+where\s+true\b)') {
  throw 'The concurrency harness contains an unscoped cleanup operation.'
}
$failureCleanup = Join-Path $root 'scripts/verify_database_concurrency_failure_cleanup.ps1'
if (-not (Test-Path -LiteralPath $failureCleanup)) { throw 'The injected concurrency cleanup verification script is missing.' }
if ($concurrencySql -notmatch 'InjectFailureAfterSetup') { throw 'The concurrency harness is missing its failure-path fixture injection.' }
$catalogChecks = Join-Path $root 'scripts/security_catalog_checks.ps1'
if (-not (Test-Path -LiteralPath $catalogChecks)) { throw 'The security catalog check script is missing.' }
$catalogSql = Get-Content -Raw $catalogChecks
foreach ($marker in @('v_expected_authenticated','v_expected_service','search_path=""','aclexplode','__codex_default_acl_probe','has_any_column_privilege','iam.memberships')) {
  if ($catalogSql -notmatch [regex]::Escape($marker)) { throw "Security catalog checks are missing: $marker" }
}
$workflow = Get-Content -Raw (Join-Path $root '.github/workflows/database.yml')
foreach ($marker in @('check_database_contract.ps1','security_review_probes.ps1','security_catalog_checks.ps1','test_database_concurrency.ps1','verify_database_concurrency_failure_cleanup.ps1','supabase db reset --local','supabase test db --local','supabase db lint --local','supabase stop --no-backup')) {
  if ($workflow -notmatch [regex]::Escape($marker)) { throw "Database CI does not include required validation step: $marker" }
}
$sequence = @('supabase db reset --local','supabase test db --local','security_review_probes.ps1','security_catalog_checks.ps1','test_database_concurrency.ps1','verify_database_concurrency_failure_cleanup.ps1','supabase test db --local','test_database_concurrency.ps1','supabase test db --local','supabase db lint --local')
$lastIndex = -1
foreach ($marker in $sequence) {
  $index = $workflow.IndexOf($marker,$lastIndex+1,[System.StringComparison]::OrdinalIgnoreCase)
  if ($index -lt 0) { throw "Database CI repeatability sequence is missing or out of order at: $marker" }
  $lastIndex = $index
}
$test = Get-Content -Raw (Join-Path $root 'supabase/tests/database/entitlements_rbac.test.sql')
$planMatch = [regex]::Match($test, 'extensions\.plan\((\d+)\)')
$assertionCount = [regex]::Matches($test, 'extensions\.(ok|is|throws_ok|lives_ok|throws_like|cmp_ok|results_eq|set_eq)\(').Count
if (-not $planMatch.Success -or [int]$planMatch.Groups[1].Value -ne $assertionCount) {
  throw "pgTAP plan/count mismatch: plan=$($planMatch.Groups[1].Value), assertions=$assertionCount"
}
Write-Output "PASS: $($required.Count) base and $($remediationRequired.Count) remediation markers, F-01/F-02 forward migration, F-03 exact cleanup harness, P-05 catalog checks, ordered CI repeatability sequence, and $assertionCount synchronized pgTAP assertions."
