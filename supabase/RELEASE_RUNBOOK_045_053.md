# Production release runbook: migrations 045 to 053

Status: PREPARED, NOT EXECUTED. Nothing here has been run on production. 051 to 053 are not applied to TEST and PR #14 is not merged. Each step below needs Mohamed's explicit go-ahead before it is run.

What I could not check: the production database. I have no access to it, so I do not know which migrations production already has. Step 0 finds out. If production is behind 044, 040 to 044 must go first (see "Earlier migrations").

## Who needs what

| Need | Why | Who has it |
| --- | --- | --- |
| Migration runner as role `postgres` (DB connection string for production, not the service key) | Every migration here is DDL or trigger/function DDL. 040's README note says apply as `postgres`. | Mohamed or whoever owns the production DB. Backend agent does not have it. |
| Supabase management API token for production | Only if the TEST-style apply (one transaction plus a `schema_migrations` insert) is used. The token used for TEST is limited to the TEST project. | Mohamed |
| Service-role key | NOT needed for any step. Do not use or paste it. | n/a |
| A low-traffic window | 045 index builds take locks (see step 1) and 048 to 053 replace functions and triggers that signed-in users call. | Mohamed |

## Step 0: preflight (read only, any time)

1. `select max(version), count(*) from supabase_migrations.schema_migrations;` Expect 202611250044 if production is two steps behind TEST, or lower. TEST is at 202611250050 (67 rows).
2. Run `supabase/e2e/verify_release_state.sql` against production (SELECT only). Before release it should show STATE_050 or lower for the function rows. After the release every function and trigger row must show STATE_053.
3. Check for stuck states that change what 050 and 052 do: `select count(*) from iam.memberships where status='suspended';` and `select count(*) from iam.member_permission_decisions where status='suspended' and not suspended_by_tenant;` Write both numbers down. Members already suspended before 050 keep their decisions suspended after reactivation (052 behavior, see step 5).
4. Take a restore point (Supabase backup or point-in-time marker). Record its id in the release log.
5. Confirm the PR #14 head SHA that Reviewer approved, and that the three files for 051 to 053 hash to the values in the PR. Confirm main CI is green.

## Step 1: migration 045, foreign key indexes (use the concurrent variant)

- Do NOT run `supabase/migrations/202611250045_fk_indexes_and_constraint_validation.sql` as is on production. It builds 94 indexes with plain `create index` inside one transaction, which blocks writes to each table while it builds.
- Run `supabase/rollouts/045_concurrent_variant.live_only.sql` with psql, one statement at a time, NOT inside a transaction (`psql -f`, no `--single-transaction`, no wrapper that adds a transaction). It uses `create index concurrently if not exists` for the same 94 indexes and ends with `alter table iam.roles validate constraint roles_tenant_family_check;`.
- After it: `select indexrelid::regclass from pg_index where not indisvalid;` must return 0 rows. A failed concurrent build leaves an INVALID index: drop it (`drop index concurrently <name>`) and re-run the file.
- Then insert the `schema_migrations` row for 202611250045 (name `fk_indexes_and_constraint_validation`) so the history matches. Use the plain 045 file's text as the stored statements.
- Rollback: `supabase/rollbacks/202611250045_fk_indexes_and_constraint_validation.rollback.sql` (drops the indexes; the validated constraint stays, which is harmless).

## Steps 2 to 5: migrations 046 to 050 (one window, in order)

Each one runs in its own transaction with its `schema_migrations` insert (statements and rollback stored), as on TEST. Run `supabase/e2e/verify_release_state.sql` after step 5.

| Step | Migration | What it does | Rollback |
| --- | --- | --- | --- |
| 2 | 046 evidence_confirm_rpc | Direct writes to `hse.evidence_files` can only create `pending`; confirming goes through `api.confirm_evidence`. No data change. Its first comment line says "DRAFT, not applied anywhere": that is stale text (it is applied on TEST) and is left alone because applied migration files are never edited. | `..046..rollback.sql` |
| 3 | 047 revoke_billing_table_select | Removes direct SELECT on `core.invoices` and `core.payments` from `authenticated`. RLS already blocked all reads, now it is a hard 42501. The UI reads through `api.platform_read_company`, unchanged. | `..047..rollback.sql` (re-grant) |
| 4 | 048 superadmin_hardening, 049 superadmin_revoke_found_fix | A company superadmin cannot change another superadmin or themselves, by direct table write or RPC. Only a platform operator can. 049 fixes the `FOUND` hole in `api.revoke_role_assignment`. | `..049..rollback.sql` then `..048..rollback.sql` |
| 5 | 050 membership_restore_on_reactivation | Creates `iam.membership_suspension_snapshots` and the suspend/reactivate restore logic. Backfills a snapshot for each member who is already suspended. | `..050..rollback.sql` (drops the snapshot table and its data, so only roll back before members are suspended again) |

## Step 6: migration 052 IMMEDIATELY after 050, same deploy

052 must run right after 050 in the same deploy on production. Do not stop, release traffic or reactivate anyone between 050 and 052. Reason: 050's backfill lists every `suspended` decision and action grant of members who are already suspended. Before 050 nothing recorded why a decision was suspended, so a decision suspended for its own reason would come back ACTIVE on reactivation. 052 empties `decision_ids` and `grant_ids` on every open snapshot. Effect on production: roles and scope rows of already-suspended members still restore on reactivation. Their decisions and action grants stay suspended after reactivation, as before 050, and an operator sets them again. Members suspended after 052 get the full restore.
Rollback: nothing to restore (the emptied lists cannot be rebuilt, and empty is the safe state).
Because the migration runner applies versions in order, run 050 and 052 back to back; 051 sorts between them, so apply 050, 051, 052 as one uninterrupted sequence.

## Step 7: migration 051, guard fixes

Three function bodies, no table or data change: a member holding an operator-origin decision can be suspended; reset contract authorizations works for protected decisions; operator `revoke_role_assignment` skips the envelope checks (a company superadmin still goes through them). Rollback: `..051..rollback.sql`.

## Step 8: migration 053, direct assignment capability guard

A direct INSERT into `iam.membership_roles`, `iam.membership_role_sites`, `iam.membership_role_org_units` now honors the same capability check as `api.assign_membership_role`. A company superadmin with limited `role_assignment` capability is refused on direct inserts to the three role tables. Platform operators and migrations (session user `postgres`) are exempt. Before this step: confirm no service-role or backend code inserts into those three tables (code audit on 2026-11-26: the backend repo at 3d7b442, the UI repo and the SQL repo contain no such insert; this does not cover other clients or the production role grants). Rollback: `..053..rollback.sql` (drops the two triggers, restores the 051 function body).

## After the release

1. `supabase/e2e/verify_release_state.sql` on production: every function and trigger row STATE_053, latest migration 202611250053, access check OK.
2. Compare the step 0 counts: member counts and suspended-decision counts unchanged.
3. Run the post-release smoke checks by hand with a platform operator login in the UI: suspend and reactivate one test member in a test company and check the restore report; try a direct role insert as a limited superadmin through the API and expect refusal.
4. Do NOT run `supabase/e2e/run_agreement_suite.sh` against production. It creates fixture users and a platform owner (inside a transaction that rolls back). Run it on a scratch clone only.

## Rollback order if something goes wrong

Reverse order, one at a time, stopping at the first step that restores service: 053, 052 (no-op), 051, 050, 049, 048, 047, 046, then 045's indexes. Each rollback file is stored in `schema_migrations.rollback` for that version on TEST; do the same on production. Delete the matching `schema_migrations` row in the same transaction.

## Not in this release

Delegation envelope restore, the 14 suspended decisions on TEST, and direct writes to `iam.roles` and `iam.role_permissions` are still open decisions for Mohamed. No `iam.roles` or `iam.role_permissions` change is part of 045 to 053.

## Earlier migrations

If production is behind 044, 040 to 044 need their own approval and are not covered here. 040 must be applied as the `postgres` role (see `supabase/README.md`).
