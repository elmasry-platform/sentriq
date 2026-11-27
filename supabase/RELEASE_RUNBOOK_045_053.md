# Production release runbook: migrations 045 to 055

Status: PREPARED, NOT EXECUTED on production. Nothing here has been run on production. On TEST, 051 to 054 were applied on 2026-11-26 (Mohamed's approval), and PR #14 and PR #15 are merged; the production release still needs Mohamed's explicit go-ahead for each step.

What I could not check: the production database. I have no access to it, so I do not know which migrations production already has. Step 0 finds out. If production is behind 044, 040 to 044 must go first (see "Earlier migrations").

## Who needs what

| Need | Why | Who has it |
| --- | --- | --- |
| Migration runner as role `postgres` (DB connection string for production, not the service key) | Every migration here is DDL or trigger/function DDL. 040's README note says apply as `postgres`. | Mohamed or whoever owns the production DB. Backend agent does not have it. |
| Supabase management API token for production | Only if the TEST-style apply (one transaction plus a `schema_migrations` insert) is used. The token used for TEST is limited to the TEST project. | Mohamed |
| Service-role key | NOT needed for any step. Do not use or paste it. | n/a |
| A low-traffic window | 045 index builds take locks (see step 1) and 048 to 053 replace functions and triggers that signed-in users call. | Mohamed |

## Step 0: preflight (read only, any time)

1. `select max(version), count(*) from supabase_migrations.schema_migrations;` Expect 202611250044 if production is two steps behind TEST, or lower. TEST is at 202611250054 (71 rows).
2. Run `supabase/e2e/verify_release_state.sql` against production (SELECT only). Before release the 051-053 rows should show STATE_050 (or UNKNOWN/MISSING if production is behind 050). After the release every row must show STATE_053 or OK. The hashes were measured on PostgreSQL 16.2 and are equal on TEST (17.6); if production runs another major version, an UNKNOWN hash means compare the function text, not an automatic failure.
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

## Step 6: migration 051, guard fixes (apply right after 050)

Three function bodies, no table or data change: a member holding an operator-origin decision can be suspended; reset contract authorizations works for protected decisions; operator `revoke_role_assignment` skips the envelope checks (a company superadmin still goes through them). Rollback: `..051..rollback.sql`.

## Step 7: migration 052, conservative snapshot decisions (apply right after 051, same uninterrupted deploy as 050)

052 must run right after 050 in the same deploy on production. Apply the sequence 050, 051, 052, 053 back to back. Do not stop, release traffic or reactivate anyone between 050 and 052. Reason: 050's backfill lists every `suspended` decision and action grant of members who are already suspended. Before 050 nothing recorded why a decision was suspended, so a decision suspended for its own reason would come back ACTIVE on reactivation. 052 empties `decision_ids` and `grant_ids` on every open snapshot. Effect on production: roles and scope rows of already-suspended members still restore on reactivation. Their decisions and action grants stay suspended after reactivation, as before 050, and an operator sets them again. Members suspended after 052 get the full restore.
Rollback: nothing to restore (the emptied lists cannot be rebuilt, and empty is the safe state).

## Step 8: migration 053, direct assignment capability guard

A direct INSERT into `iam.membership_roles`, `iam.membership_role_sites`, `iam.membership_role_org_units` now honors the same capability check as `api.assign_membership_role`. A company superadmin with limited `role_assignment` capability is refused on direct inserts to the three role tables. Platform operators and migrations (session user `postgres`) are exempt. Before this step: confirm no service-role or backend code inserts into those three tables (code audit on 2026-11-26: the backend repo at 3d7b442, the UI repo and the SQL repo contain no such insert; this does not cover other clients or the production role grants). Rollback: `..053..rollback.sql` (drops the two triggers, restores the 051 body of `private.guard_assigned_role_authority`).

## Step 9: migration 054, company Admin sees only Employee-level members (after 053; PR #15, merged)

A company Admin sees only members whose `member_role` is `employee` (and themselves), never the Superadmin or other Admins. Applies to the Team page (`iam.memberships` read policy `membership_read`, feeding `api.v_memberships`) and to `api.company_member_permission_decisions` (for an Admin: rows of employees and self only; `granted_by_email` only when the Admin granted it). Level comes from `iam.memberships.member_role` only, so temporary permissions, delegations and grants cannot widen it. Superadmin and platform operator reads are unchanged. Adds `private.is_active_company_admin(uuid)` (execute for `authenticated` only). No data change. Source of the rule: Mohamed, message 22633562, relayed by Main; not yet approved as an ADR line. Rollback: `..054..rollback.sql` (restores the 053-state policy and function).
Preconditions: PR #15 merged (CI green after #14: Files=31, Tests=1243), applied to TEST first (done 2026-11-26) with `verify_release_state.sql` showing STATE_054 on the 054 rows, and the 054 rollback replayed.

## Step 10: migration 055, company Admin reads site assignments of Employee-level members (after 054; PR #18)

A company Admin can read `iam.site_access` rows of Employee-level members of the same company (and their own rows), never Superadmin rows, never other Admin rows, never another company. Level comes from `iam.memberships.member_role` only, so temporary permissions, delegations and grants cannot widen it. Read only: `site_access_insert` and `site_access_update` are not touched. Effect: `api.v_memberships."siteIds"` now returns the employees' site ids for an Admin. Adds `private.admin_can_read_employee_member(uuid,uuid)` (execute for authenticated only, not anon, not service_role), replaces policy `site_access_read`. Independent of 054. No data change. Rollback: `supabase/rollbacks/202611250055_admin_reads_employee_site_access.rollback.sql`.
Preconditions: PR #18 merged (CI Files=32, Tests=1267), applied to TEST first with `verify_release_state.sql` showing STATE_055 on the 055 rows, and the 055 rollback replayed. Visible `granted_by` user ids on site rows are readable by the Admin for those employee rows.

## Gate before production: TEST apply and rollback replay of 051 to 054 (done on TEST, 2026-11-26)

Done: 051, 052 and 053 were applied to TEST in one transaction (with the `schema_migrations` rows holding statements and rollback), then 054 in its own transaction; each had a rolled-back dry run first. `verify_release_state.sql` on TEST shows STATE_053 on the 051 to 053 rows and STATE_054 on the 054 rows. The rollbacks of 053, 052 and 051 were replayed on a scratch clone (not TEST) and every 051 to 053 row went back to its STATE_050 hash. Counts before and after were equal (10 memberships, 14 suspended decisions, 1884 audit rows). 052 changes nothing on TEST data (0 snapshots).

Still needed for production: Mohamed's explicit word for each production step, and the step 0 preflight on the production database.
## File hashes (sha256, first 10 characters, each file ends with exactly one trailing newline)

Measured by the backend agent on branch docs/release-runbook-045-053 (same bytes as PR #14 and main).

| File | sha256 (10) |
| --- | --- |
| 045 plain migration | 2bceeeb139 |
| 045 concurrent variant (rollouts) | 2bd97e59c3 |
| 046 | 618f60d62d |
| 047 | 9ddc26b524 |
| 048 | b93845ed1a |
| 049 | 8076d545da |
| 050 | 0b81043466 |
| 051 | de1f2f49dc |
| 052 | 52418213ea |
| 053 | 5ab0d6fb38 |
| 054 (PR #15) | 0ae975e92f |
| 045 rollback | 5e948ab2ab |
| 046 rollback | 0b3bb5b32e |
| 047 rollback | c493521107 |
| 048 rollback | 78978ee40a |
| 049 rollback | 0f252773ad |
| 050 rollback | d15515ec75 |
| 051 rollback | b385ef8731 |
| 052 rollback | 91aa870f07 |
| 053 rollback | e1bdb71d1f |
| 054 rollback (PR #15) | a7b652c9c3 |
| 055 (PR #18) | 6e7e11a6e0 |
| 055 rollback (PR #18) | b54e2b17d2 |

Check before applying: `sha256sum <file> | cut -c1-10` must equal the table.

## Sign-up gate, auto-confirm and hook: check before and after

Read-only. I do not change any Auth setting (no SMTP or Auth changes are part of this release).
1. Hook function present and callable by the auth admin role: `select has_function_privilege('supabase_auth_admin','private.before_user_created_hook(jsonb)','execute');` must be true, and the same check for `anon`, `authenticated` and `service_role` must be false. (Run `\df private.before_user_created_hook` first to confirm the exact signature on production.)
2. Dashboard check, done by Mohamed (I have no production dashboard access): Auth, Hooks, "Before user created" is enabled and points to `private.before_user_created_hook`. In the repo `supabase/config.toml` has `enable_confirmations = false` for local only; the production auto-confirm setting is a dashboard value and must be read there. It must be OFF before real customers (see the gate list).
3. Canary: `scripts/signup_gate_canary.sh` against the real Auth server of a non-production clone: a sign-up without an invitation is rejected, with a valid invitation it is allowed.
4. After the release repeat 1 and 2 and confirm nothing changed.

## Before real customers: gate list (each needs an owner decision, none is done by this release)

1. MFA for Owner and Sub-owner accounts enabled and enforced.
2. Auth auto-confirm turned off (email must be verified).
3. Storage bucket size and file type limits set on the evidence bucket.
4. Orphan cleanup for evidence objects that were uploaded but never confirmed (pending rows and stored objects).
5. Download headers: serve uploads with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, never inline (046 accepts `application/octet-stream`, so the mime check is not a security control).
6. ADR 0001, 0002 and 0003 approved by Mohamed (they are in the `ADR` folder).

## After the release

1. `supabase/e2e/verify_release_state.sql` on production: every function and trigger row STATE_053, latest migration 202611250053, access check OK.
2. Compare the step 0 counts: member counts and suspended-decision counts unchanged.
3. Run the post-release smoke checks by hand with a platform operator login in the UI: suspend and reactivate one test member in a test company and check the restore report; try a direct role insert as a limited superadmin through the API and expect refusal.
4. Do NOT run `supabase/e2e/run_agreement_suite.sh` against production. It creates fixture users and a platform owner (inside a transaction that rolls back). Run it on a scratch clone only.

## Rollback order if something goes wrong

Reverse order, one at a time, stopping at the first step that restores service: 055 (if applied), 054 (if applied), 053, 052 (no-op), 051, 050, 049, 048, 047, 046, then 045's indexes. Each rollback file is stored in `schema_migrations.rollback` for that version on TEST; do the same on production. Delete the matching `schema_migrations` row in the same transaction.

## Not in this release

Delegation envelope restore, the 14 suspended decisions on TEST, and direct writes to `iam.roles` and `iam.role_permissions` are still open decisions for Mohamed. No `iam.roles` or `iam.role_permissions` change is part of 045 to 053.

## Earlier migrations

If production is behind 044, 040 to 044 need their own approval and are not covered here. 040 must be applied as the `postgres` role (see `supabase/README.md`).
