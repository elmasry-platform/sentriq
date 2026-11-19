$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$migration = Get-Content -Raw (Join-Path $root 'supabase/migrations/202611190002_commercial_entitlements_rbac.sql')
$sql = $migration.ToLowerInvariant()
$required = @(
  'core.features', 'core.plans', 'core.plan_entitlements', 'core.subscriptions',
  'core.subscription_items', 'core.entitlement_grants', 'core.usage_events', 'core.invoices',
  'core.invoice_items', 'core.payments', 'iam.roles', 'iam.role_permissions',
  'iam.membership_roles', 'iam.org_unit_access', 'iam.invitations',
  'private.has_feature_entitlement', 'api.record_feature_usage', 'api.invoice_usage_event',
  'private.audit_row_change', 'private.guard_audit_immutable'
)
$missing = @($required | Where-Object { $sql -notmatch [regex]::Escape($_) })
if ($missing.Count -gt 0) { throw "Missing required contract markers: $($missing -join ', ')" }
foreach ($unsafe in @(
  'create policy org_write on core.org_units for all',
  'create policy membership_write on iam.memberships for all',
  'create policy followups_write on hse.follow_ups for all',
  'grant execute on function api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb) to authenticated',
  'insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by)'
)) {
  if ($sql.Contains($unsafe)) { throw "Unsafe or legacy path found: $unsafe" }
}
if ($sql -notmatch 'grant execute on function api\.record_feature_usage\(uuid,uuid,text,text,numeric,text,jsonb\) to service_role') {
  throw 'The usage recorder is not granted to service_role.'
}
Write-Output "PASS: $($required.Count) contract markers, no listed FOR ALL delete policies, and service_role-only usage recording."
