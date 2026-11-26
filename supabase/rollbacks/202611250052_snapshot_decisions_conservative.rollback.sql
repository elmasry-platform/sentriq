-- Rollback for 052: nothing to restore. The emptied lists cannot be rebuilt, and an empty list is the safe state.
-- (Members reactivated after 052 keep their decisions suspended; set them again if needed.)
select 1;
