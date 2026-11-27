$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$migrations = Get-ChildItem (Join-Path $root 'supabase/migrations') -Filter '*.sql' | Sort-Object Name
$sql = (($migrations | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n").ToLowerInvariant()
$forwardMigrations = @($migrations | Where-Object { $_.Name -ne '202611190001_sentriq_hse.sql' })
$forwardSql = (($forwardMigrations | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n").ToLowerInvariant()
$remediationMigration = Join-Path $root 'supabase/migrations/202611200002_foundation_security_remediation.sql'
$remediationSql = (Get-Content -Raw $remediationMigration).ToLowerInvariant()
$phase1SecurityMigration = Join-Path $root 'supabase/migrations/202611230001_phase1_permission_and_tenant_guards.sql'
$phase1SecuritySql = (Get-Content -Raw $phase1SecurityMigration).ToLowerInvariant()
$legacyAuthorizationMigration = Join-Path $root 'supabase/migrations/202611240001_legacy_hse_authorization_refactor.sql'
$legacyAuthorizationSql = (Get-Content -Raw $legacyAuthorizationMigration).ToLowerInvariant()
$permissionCompletionMigrations = @(
  '202611240002_phase1_permission_completion.sql',
  '202611240003_phase1_profile_version_cursor.sql',
  '202611240004_phase1_permission_policy_acl.sql',
  '202611240005_phase1_profile_target_alias.sql',
  '202611240006_phase1_profile_version_query_alias.sql',
  '202611240007_phase1_rls_initplan_optimization.sql',
  '202611240008_phase1_member_permission_rls_initplan.sql'
)
$permissionCompletionSql = (($permissionCompletionMigrations | ForEach-Object {
  Get-Content -Raw (Join-Path $root "supabase/migrations/$_")
}) -join "`n").ToLowerInvariant()
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
$phase1SecurityRequired = @(
  'create or replace function private.can_manage_tenant',
  'm.member_role=''company_superadmin''',
  'tenant_id_is_immutable',
  'join iam.role_versions rv',
  'new.role_version_id is null',
  'roles_phase1_family_not_null_check',
  'specific_override',
  'o.scope_kind=d.scope_kind',
  'd.scope_kind=''tenant'' and o.scope_kind in (''site'',''org_unit'',''assigned_task'')'
)
$missingPhase1Security = @($phase1SecurityRequired | Where-Object { $phase1SecuritySql -notmatch [regex]::Escape($_) })
if ($missingPhase1Security.Count -gt 0) { throw "Missing Phase 1 security remediation markers: $($missingPhase1Security -join ', ')" }
if ($phase1SecuritySql -match '(?is)union\s+all\s+select\s+rp\.scope_kind.*?mr\.role_version_id\s+is\s+null') {
  throw 'A Phase 1 permission evaluator retains the unversioned role fallback.'
}
$legacyAuthorizationRequired = @(
  'create or replace function private.legacy_global_hse_permission_allowed',
  "r.tenant_id is null and r.protected",
  "r.role_family='employee'",
  'create or replace function private.can_access_hse',
  'private.phase1_permission_allowed(p_tenant_id,p_permission',
  'create or replace function api.can_use_feature',
  'drop policy if exists audit_read on audit.events',
  'using(user_id=auth.uid() or private.can_manage_tenant(tenant_id))',
  'actor_membership_id=private.current_membership_id(tenant_id)',
  "private.phase1_permission_allowed(tenant_id,'hse.audit.read'"
)
$missingLegacyAuthorization = @($legacyAuthorizationRequired | Where-Object { $legacyAuthorizationSql -notmatch [regex]::Escape($_) })
if ($missingLegacyAuthorization.Count -gt 0) { throw "Missing D-30 legacy authorization markers: $($missingLegacyAuthorization -join ', ')" }
if ($legacyAuthorizationSql -match '(?is)(select\s+private\.is_platform_operator|or\s+private\.is_platform_operator|select\s+private\.has_hse_permission|or\s+private\.has_hse_permission)') {
  throw 'The D-30 legacy HSE migration calls a broad platform or legacy permission helper.'
}
$permissionCompletionRequired = @(
  'iam.permission_profile_defaults', 'iam.delegation_review_events',
  'api.set_default_permission_profile', 'api.set_member_permission_decision',
  'api.create_delegation', 'api.revoke_delegation', 'api.review_delegation',
  'api.set_superadmin_capability_limit', 'api.create_company_invitation',
  'api.create_company_superadmin_invitation', 'api.assign_membership_role',
  'private.guard_delegation_envelope', 'private.revoke_delegation_tree',
  'private.apply_invitation_phase1_defaults', 'delegation_parent_same_tenant_fkey',
  'from public,anon,authenticated,service_role', 'force row level security',
  'selected_existing_users', 'specific_override', 'auth.uid()',
  'create policy contractor_org_insert', 'create policy engagement_insert',
  'create policy permission_profile_applications_read',
  'create policy member_permissions_insert', 'create policy member_permissions_read'
)
$missingPermissionCompletion = @($permissionCompletionRequired | Where-Object { $permissionCompletionSql -notmatch [regex]::Escape($_) })
if ($missingPermissionCompletion.Count -gt 0) { throw "Missing Phase 1 permission completion markers: $($missingPermissionCompletion -join ', ')" }
$gatedSignupSql = ((@('202611250043_invitation_gated_signup.sql','202611250044_signup_gate_hardening.sql') | ForEach-Object {
  Get-Content -Raw (Join-Path $root "supabase/migrations/$_")
}) -join "`n").ToLowerInvariant()
$gatedSignupRequired = @(
  'private.validate_signup_invitation', 'api.preview_invitation', 'private.before_user_created_hook',
  'signup_requires_valid_invitation', "'error',jsonb_build_object('http_code',403", 'exception when others then',
  'grant usage on schema api to anon', 'grant execute on function api.preview_invitation(text) to anon,authenticated',
  'revoke all on function private.validate_signup_invitation(text,text),private.before_user_created_hook(jsonb) from public,anon,authenticated,service_role',
  'supabase_auth_admin', 'alter default privileges for role postgres in schema api revoke execute on functions from public, anon',
  'private.spent_signup_tokens_in_user_metadata'
)
$missingGatedSignup = @($gatedSignupRequired | Where-Object { $gatedSignupSql -notmatch [regex]::Escape($_) })
if ($missingGatedSignup.Count -gt 0) { throw "Missing invitation-gated signup markers: $($missingGatedSignup -join ', ')" }
if ($gatedSignupSql -match '(?is)(insert\s+into\s+auth\.|update\s+auth\.|delete\s+from\s+auth\.)') { throw 'The signup gate migrations must not write to auth tables.' }
$configToml = (Get-Content -Raw (Join-Path $root 'supabase/config.toml'))
if ($configToml -notmatch '(?is)\[auth\.hook\.before_user_created\]\s*enabled\s*=\s*true\s*uri\s*=\s*"pg-functions://postgres/private/before_user_created_hook"') {
  throw 'supabase/config.toml must wire the before-user-created hook to private.before_user_created_hook.'
}
if (-not (Test-Path -LiteralPath (Join-Path $root 'scripts/signup_gate_canary.sh'))) { throw 'The signup gate canary script is missing.' }
$expectedLatestMigration = '202611250059_hse_form_permission_keys.sql'
if ($migrations[-1].Name -ne $expectedLatestMigration) {
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
$testFiles = @(Get-ChildItem (Join-Path $root 'supabase/tests/database') -Filter '*.test.sql' | Sort-Object Name)
$totalAssertions = 0
foreach ($testFile in $testFiles) {
  $test = Get-Content -Raw $testFile.FullName
  $planMatches = [regex]::Matches($test, 'extensions\.plan\((\d+)\)')
  $assertions = [regex]::Matches($test, 'extensions\.(ok|is|throws_ok|lives_ok|throws_like|cmp_ok|results_eq|set_eq)\(').Count
  if ($planMatches.Count -ne 1 -or [int]$planMatches[0].Groups[1].Value -ne $assertions) {
    throw "pgTAP plan/count mismatch in $($testFile.Name): plan=$($planMatches[0].Groups[1].Value), assertions=$assertions"
  }
  $totalAssertions += $assertions
}
# Drift guard for the 052 copies embedded in the pgTAP test (same rule as scripts/check_052_embed.sh, line endings normalized for the Windows runner).
$m052 = ((Get-Content -Raw (Join-Path $root 'supabase/migrations/202611250052_snapshot_decisions_conservative.sql')) -replace "`r`n", "`n")
$t052 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/snapshot_conservative_052.test.sql')) -replace "`r`n", "`n")
$blocks052 = [regex]::Matches($t052, '(?ms)^-- BEGIN EMBEDDED 052[^\n]*\n(.*?)^-- END EMBEDDED 052')
if ($blocks052.Count -lt 1) { throw 'No embedded 052 block found in snapshot_conservative_052.test.sql.' }
foreach ($blk in $blocks052) {
  if ($blk.Groups[1].Value -ne $m052) { throw 'DRIFT: an embedded 052 copy in snapshot_conservative_052.test.sql differs from the 052 migration file.' }
}
# Drift guard for the 054 copies embedded in the pgTAP test (same rule as scripts/check_054_embed.sh: migration and rollback; line endings normalized for the Windows runner).
$t054 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/team_visibility_054.test.sql')) -replace "`r`n", "`n")
$pairs054 = @(
  @{ Name = 'migration'; File = 'supabase/migrations/202611250054_admin_sees_lower_members.sql'; Begin = '-- BEGIN EMBEDDED 054'; End = '-- END EMBEDDED 054' },
  @{ Name = 'rollback'; File = 'supabase/rollbacks/202611250054_admin_sees_lower_members.rollback.sql'; Begin = '-- BEGIN EMBEDDED 054 ROLLBACK'; End = '-- END EMBEDDED 054 ROLLBACK' }
)
foreach ($pair in $pairs054) {
  $want054 = ((Get-Content -Raw (Join-Path $root $pair.File)) -replace "`r`n", "`n")
  $rx054 = '(?ms)^' + [regex]::Escape($pair.Begin) + '\n(.*?)^' + [regex]::Escape($pair.End) + '$'
  $blocks054 = [regex]::Matches($t054, $rx054)
  if ($blocks054.Count -lt 1) { throw "No embedded 054 $($pair.Name) block found in team_visibility_054.test.sql." }
  foreach ($blk in $blocks054) {
    if ($blk.Groups[1].Value -ne $want054) { throw "DRIFT: an embedded 054 $($pair.Name) copy in team_visibility_054.test.sql differs from $($pair.File)." }
  }
}
# Drift guard for the 055 copies embedded in the pgTAP test (same rule as scripts/check_055_embed.sh: migration and rollback; line endings normalized for the Windows runner).
$t055 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/team_site_access_055.test.sql')) -replace "`r`n", "`n")
$pairs055 = @(
  @{ Name = 'migration'; File = 'supabase/migrations/202611250055_admin_reads_employee_site_access.sql'; Begin = '-- BEGIN EMBEDDED 055'; End = '-- END EMBEDDED 055' },
  @{ Name = 'rollback'; File = 'supabase/rollbacks/202611250055_admin_reads_employee_site_access.rollback.sql'; Begin = '-- BEGIN EMBEDDED 055 ROLLBACK'; End = '-- END EMBEDDED 055 ROLLBACK' }
)
foreach ($pair in $pairs055) {
  $want055 = ((Get-Content -Raw (Join-Path $root $pair.File)) -replace "`r`n", "`n")
  $rx055 = '(?ms)^' + [regex]::Escape($pair.Begin) + '\n(.*?)^' + [regex]::Escape($pair.End) + '$'
  $blocks055 = [regex]::Matches($t055, $rx055)
  if ($blocks055.Count -lt 1) { throw "No embedded 055 $($pair.Name) block found in team_site_access_055.test.sql." }
  foreach ($blk in $blocks055) {
    if ($blk.Groups[1].Value -ne $want055) { throw "DRIFT: an embedded 055 $($pair.Name) copy in team_site_access_055.test.sql differs from $($pair.File)." }
  }
}
# Drift guard for the 056 copies embedded in the pgTAP test (migration and rollback; line endings normalized).
$t056 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/evidence_bucket_limits_056.test.sql')) -replace "`r`n", "`n")
$pairs056 = @(
  @{ Name = 'migration'; File = 'supabase/migrations/202611250056_evidence_bucket_limits.sql'; Begin = '-- BEGIN EMBEDDED 056'; End = '-- END EMBEDDED 056' },
  @{ Name = 'rollback'; File = 'supabase/rollbacks/202611250056_evidence_bucket_limits.rollback.sql'; Begin = '-- BEGIN EMBEDDED 056 ROLLBACK'; End = '-- END EMBEDDED 056 ROLLBACK' }
)
foreach ($pair in $pairs056) {
  $want056 = ((Get-Content -Raw (Join-Path $root $pair.File)) -replace "`r`n", "`n")
  $rx056 = '(?ms)^' + [regex]::Escape($pair.Begin) + '\n(.*?)^' + [regex]::Escape($pair.End) + '$'
  $blocks056 = [regex]::Matches($t056, $rx056)
  if ($blocks056.Count -lt 1) { throw "No embedded 056 $($pair.Name) block found in evidence_bucket_limits_056.test.sql." }
  foreach ($blk in $blocks056) {
    if ($blk.Groups[1].Value -ne $want056) { throw "DRIFT: an embedded 056 $($pair.Name) copy in evidence_bucket_limits_056.test.sql differs from $($pair.File)." }
  }
}
# Drift guard for the 057 copies embedded in the pgTAP test (migration and rollback; line endings normalized).
$t057 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/platform_operator_aal2_057.test.sql')) -replace "`r`n", "`n")
$pairs057 = @(
  @{ Name = 'migration'; File = 'supabase/migrations/202611250057_platform_operator_aal2.sql'; Begin = '-- BEGIN EMBEDDED 057'; End = '-- END EMBEDDED 057' },
  @{ Name = 'rollback'; File = 'supabase/rollbacks/202611250057_platform_operator_aal2.rollback.sql'; Begin = '-- BEGIN EMBEDDED 057 ROLLBACK'; End = '-- END EMBEDDED 057 ROLLBACK' }
)
foreach ($pair in $pairs057) {
  $want057 = ((Get-Content -Raw (Join-Path $root $pair.File)) -replace "`r`n", "`n")
  $rx057 = '(?ms)^' + [regex]::Escape($pair.Begin) + '\n(.*?)^' + [regex]::Escape($pair.End) + '$'
  $blocks057 = [regex]::Matches($t057, $rx057)
  if ($blocks057.Count -lt 1) { throw "No embedded 057 $($pair.Name) block found in platform_operator_aal2_057.test.sql." }
  foreach ($blk in $blocks057) {
    if ($blk.Groups[1].Value -ne $want057) { throw "DRIFT: an embedded 057 $($pair.Name) copy in platform_operator_aal2_057.test.sql differs from $($pair.File)." }
  }
}

# Drift guard for the 058 copies embedded in the pgTAP test (migration and rollback; line endings normalized).
$t058 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/hse_form_template_lifecycle_058.test.sql')) -replace "`r`n", "`n")
$pairs058 = @(
  @{ Name = 'migration'; File = 'supabase/migrations/202611250058_hse_form_template_lifecycle.sql'; Begin = '-- BEGIN EMBEDDED 058'; End = '-- END EMBEDDED 058' },
  @{ Name = 'rollback'; File = 'supabase/rollbacks/202611250058_hse_form_template_lifecycle.rollback.sql'; Begin = '-- BEGIN EMBEDDED 058 ROLLBACK'; End = '-- END EMBEDDED 058 ROLLBACK' }
)
foreach ($pair in $pairs058) {
  $want058 = ((Get-Content -Raw (Join-Path $root $pair.File)) -replace "`r`n", "`n")
  $rx058 = '(?ms)^' + [regex]::Escape($pair.Begin) + '\n(.*?)^' + [regex]::Escape($pair.End) + '$'
  $blocks058 = [regex]::Matches($t058, $rx058)
  if ($blocks058.Count -lt 1) { throw "No embedded 058 $($pair.Name) block found in hse_form_template_lifecycle_058.test.sql." }
  foreach ($blk in $blocks058) {
    if ($blk.Groups[1].Value -ne $want058) { throw "DRIFT: an embedded 058 $($pair.Name) copy in hse_form_template_lifecycle_058.test.sql differs from $($pair.File)." }
  }
}
# Drift guard for the 059 copies embedded in the pgTAP test (migration and rollback; line endings normalized).
$t059 = ((Get-Content -Raw (Join-Path $root 'supabase/tests/database/hse_form_permission_keys_059.test.sql')) -replace "`r`n", "`n")
$pairs059 = @(
  @{ Name = 'migration'; File = 'supabase/migrations/202611250059_hse_form_permission_keys.sql'; Begin = '-- BEGIN EMBEDDED 059'; End = '-- END EMBEDDED 059' },
  @{ Name = 'rollback'; File = 'supabase/rollbacks/202611250059_hse_form_permission_keys.rollback.sql'; Begin = '-- BEGIN EMBEDDED 059 ROLLBACK'; End = '-- END EMBEDDED 059 ROLLBACK' }
)
foreach ($pair in $pairs059) {
  $want059 = ((Get-Content -Raw (Join-Path $root $pair.File)) -replace "`r`n", "`n")
  $rx059 = '(?ms)^' + [regex]::Escape($pair.Begin) + '\n(.*?)^' + [regex]::Escape($pair.End) + '$'
  $blocks059 = [regex]::Matches($t059, $rx059)
  if ($blocks059.Count -lt 1) { throw "No embedded 059 $($pair.Name) block found in hse_form_permission_keys_059.test.sql." }
  foreach ($blk in $blocks059) {
    if ($blk.Groups[1].Value -ne $want059) { throw "DRIFT: an embedded 059 $($pair.Name) copy in hse_form_permission_keys_059.test.sql differs from $($pair.File)." }
  }
}
Write-Output "PASS: $($required.Count) base, $($remediationRequired.Count) foundation remediation, $($phase1SecurityRequired.Count) Phase 1 security markers, $($permissionCompletionRequired.Count) permission completion markers, D-30 forward remediation, P-05 catalog checks, ordered CI repeatability sequence, and $totalAssertions synchronized assertions across $($testFiles.Count) pgTAP files."
