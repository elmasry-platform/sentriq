#!/usr/bin/env bash
# Agreement end-to-end suite. Runs every pgTAP file in supabase/tests/database against a DISPOSABLE database that
# has all migrations applied (supabase db reset --local, or a scratch clone). Each file runs in its own transaction
# and rolls back. Do NOT point this at TEST or production: the files create fixture users in auth.users and
# bootstrap a platform owner inside the transaction.
# Usage: run_agreement_suite.sh "<psql connection string or -d dbname args>"   e.g. "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
# Exit code 0 only when every file ran its full plan, with 0 failed assertions and 0 SQL errors.
set -uo pipefail
PSQL="${PSQL:-psql}"
CONN="${1:?connection string required}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$ROOT/supabase/tests/database"
declare -A AREA=(
  [superadmin_hardening]="roles" [delegation_escalation]="roles+delegation" [direct_assignment_guard_053]="roles"
  [guard_fixes_051]="roles+suspend" [iam_contract_boundaries]="roles+rls" [phase1_permission_completion]="roles"
  [phase1_security_remediation]="roles+rls" [action_write_guards]="rls"
  [membership_restore]="suspend/reactivate" [restore_matrix]="suspend/reactivate" [snapshot_conservative_052]="suspend/reactivate"
  [delegated_role_tenant_restore]="delegation+suspend" [delegation_tenant_restore]="delegation+suspend"
  [invitation_gated_signup]="invitations" [invitations_operator_initial_access]="invitations" [invitations_review2]="invitations"
  [invitations_review3]="invitations" [platform_create_company]="invitations"
  [entitlements_rbac]="rls" [dynamic_member_entitlements]="rls" [dynamic_member_entitlements_company_deny]="rls"
  [dynamic_member_entitlements_review]="rls" [hse_billing_audit_isolation]="rls" [billing_tables_no_direct_select]="rls"
  [workspaces_view_isolation]="rls" [phase1_people_isolation]="rls" [storage_evidence_policies]="rls"
  [evidence_confirm_fix]="rls" [evidence_files_write_guards]="rls" [fk_index_and_constraint_contract]="rls"
)
printf '%-48s %-22s %6s %6s %6s %6s\n' file area plan ok notok errors
tp=0; tok=0; bad=0
for f in "$T"/*.test.sql; do
  b=$(basename "$f" .test.sql)
  out=$($PSQL $CONN -qAtX -f "$f" 2>&1)
  plan=$(echo "$out" | grep -m1 -oE '^1\.\.[0-9]+' | cut -d. -f3)
  ok=$(echo "$out" | grep -cE '^ok')
  nok=$(echo "$out" | grep -ciE '^not ok')
  err=$(echo "$out" | grep -cE 'ERROR:')
  plan=${plan:-0}
  flag=""
  if [ "$ok" -ne "$plan" ] || [ "$nok" -ne 0 ] || [ "$err" -ne 0 ]; then flag="  <== FAIL"; bad=$((bad+1)); fi
  printf '%-48s %-22s %6s %6s %6s %6s%s\n' "$b" "${AREA[$b]:-UNMAPPED}" "$plan" "$ok" "$nok" "$err" "$flag"
  tp=$((tp+plan)); tok=$((tok+ok))
done
echo "TOTAL planned=$tp passed=$tok files_failing=$bad"
[ "$bad" -eq 0 ] && [ "$tp" -eq "$tok" ] && { echo "RESULT: PASS"; exit 0; }
echo "RESULT: FAIL"; exit 1
