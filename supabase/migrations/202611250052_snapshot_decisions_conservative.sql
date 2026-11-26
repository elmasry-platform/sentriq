-- 052: make the 050 backfill safe without editing 050.
-- 050 already ran on TEST (zero suspended members then). Where 050 has not run yet (production), its backfill
-- lists, for members that are already suspended, every decision and action grant with status 'suspended'.
-- Before 050 nothing recorded WHY a decision was suspended, so one suspended for its own reason would come back
-- ACTIVE when its member is reactivated. This migration empties decision_ids and grant_ids on every OPEN snapshot
-- that exists when it runs (open = member currently suspended, snapshot not yet used).
-- What it does for a production apply where members are already suspended:
--   * their roles and scope rows are still restored on reactivation (digest kept);
--   * their decisions and action grants stay suspended after reactivation, as before 050 (set them again);
--   * members suspended AFTER this migration get the full restore (snapshot taken by the trigger).
-- On TEST: no open snapshots, no rows change. Run it right after 050. Plain PostgreSQL, data change only on this table.
update iam.membership_suspension_snapshots
   set decision_ids='{}', grant_ids='{}'
 where status='open' and (cardinality(decision_ids)>0 or cardinality(grant_ids)>0);
-- drift probe
