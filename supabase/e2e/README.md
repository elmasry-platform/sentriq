# Agreement end-to-end suite

IMPORTANT, plainly: this is a DATABASE-level suite (PostgreSQL functions, triggers, privileges, RLS, run as SQL with pgTAP). It does not test PostgREST (the HTTP API layer), Supabase Storage, Auth server behavior, the NestJS backend or the UI. A pass here does not prove those layers. The sign-up canary (`scripts/signup_gate_canary.sh`) is the only script that touches the real Auth server, and UI behavior is covered only by the QA runs on the preview.

Two tools, both for review and runs by Reviewer, QA and Data Engineer.

1. `run_agreement_suite.sh "<psql connection>"` runs all 32 pgTAP files (roles, suspend and reactivate, delegation, invitations, RLS and privileges) against a disposable database that already has all migrations (`supabase db reset --local`, or a scratch clone). Each file is its own transaction and rolls back. It prints one row per file with its area, planned and passed counts and exits 0 only on a full pass. Needs real pgTAP (the CI database has it). The script exits 2 if the database is unreachable and fails (exit 1) when psql errors, when a file plans 0 tests, when passed differs from planned, or when the number of files run is not 31. Never run it on TEST or production: the files create fixture users in `auth.users` inside the transaction.
   Expected result: 32 files, 1267 planned tests with #14, #15 and #18; 31 files, 1243 without 055; 30 files, 1223 without 054 and 055.
   The concurrency checks (`scripts/test_database_concurrency.ps1`) are separate and run in CI.
2. `verify_release_state.sql` is SELECT only and safe on TEST and production. It reports whether function bodies, triggers, ACLs and the latest migration match state 050, state 053, state 054 or state 055. Measured: TEST before 055 = STATE_054 (051 to 053 rows STATE_053, 054 rows STATE_054, 055 rows STATE_054); a clone with 051 to 053 only = STATE_053.

## What each area proves (agreement rules)

| Area | Rule | Files |
| --- | --- | --- |
| Roles | Owner and Sub-owner can do everything unless the Owner withdraws a power. A superadmin cannot change another superadmin or themselves, only a platform operator can. A limited superadmin cannot assign roles by direct insert (053). Operator revoke skips envelope checks (051). | superadmin_hardening (130), direct_assignment_guard_053 (18), guard_fixes_051 (27), iam_contract_boundaries (97), phase1_permission_completion (30), phase1_security_remediation (15), delegation_escalation (32) |
| Suspend and reactivate | Reactivation restores what suspension took away, only that, and nothing else. Already-suspended decisions stay suspended (052). Ended or invited members get a clean slate. | membership_restore (41), restore_matrix (28), snapshot_conservative_052 (8), delegated_role_tenant_restore (54), delegation_tenant_restore (48) |
| Delegation | Delegation only down, never escalates; ending a source ends the delegated access; envelopes are not restored by reactivation. | delegation_escalation (32), delegation_tenant_restore (48), delegated_role_tenant_restore (54) |
| Invitations | Signup only through a valid invitation; operator-issued first access; company creation by operators. | invitation_gated_signup (31), invitations_operator_initial_access (37), invitations_review2 (7), invitations_review3 (13), platform_create_company (8) |
| RLS and privileges | Tenant isolation, no direct billing reads, evidence and storage rules, entitlement gates, every FK indexed. | entitlements_rbac (242), dynamic_member_entitlements* (69, 19, 36), hse_billing_audit_isolation (69), billing_tables_no_direct_select (16), workspaces_view_isolation (12), phase1_people_isolation (26), storage_evidence_policies (23), evidence_confirm_fix (36), evidence_files_write_guards (17), action_write_guards (30), fk_index_and_constraint_contract (4), team_visibility_054 (20, a company Admin sees only Employee-level members; level from member_role only) |
