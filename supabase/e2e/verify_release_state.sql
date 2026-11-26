-- READ-ONLY release state check. Safe on TEST or production (SELECT only, no writes).
-- Returns one row per check. 'state_050' = expected right after migration 050, 'state_053' = expected after 051-053.
-- Function hashes are left(md5(pg_get_functiondef(oid)),10), measured on a replay of the repo migrations.
with fn(name, h050, h053) as (values
  ('api.membership_restore_report(uuid,uuid)','511c70f6f3','511c70f6f3'),
  ('api.revoke_role_assignment(uuid,uuid,text)','21247eb117','83fd57226d'),
  ('private.guard_assigned_role_authority()','413c92b4d4','cc97afba45'),
  ('private.guard_decision_authority()','02553cb05b','bb6281eafe'),
  ('private.reset_contract_authorizations()','0dbbc972a6','4401bff767'),
  ('private.guard_role_scope_row_authority()',null,'ffc2dce004')),
actual as (select p.oid::regprocedure::text as name, p.oid, left(md5(pg_get_functiondef(p.oid)),10) as h from pg_proc p where p.prokind='f' and p.pronamespace in ('api'::regnamespace,'private'::regnamespace)),
rows_fn as (
  select 'function '||fn.name as check_name, fn.h050 as state_050, fn.h053 as state_053, a.h as actual,
         case when a.h is not distinct from fn.h053 then 'STATE_053' when a.h is not distinct from fn.h050 then 'STATE_050' else 'UNKNOWN' end as matches
  from fn left join actual a on a.name = fn.name),
rows_trg as (
  select 'trigger a01_role_scope_row_authority on sites+org_units' as check_name, null::text, '2 enabled',
         (select count(*)::text||' enabled' from pg_trigger where tgname='a01_role_scope_row_authority' and tgenabled='O' and not tgisinternal) as actual,
         case when (select count(*) from pg_trigger where tgname='a01_role_scope_row_authority' and tgenabled='O' and not tgisinternal)=2 then 'STATE_053' else 'STATE_050' end),
rows_acl as (
  select 'no client can execute guard functions (anon, authenticated, service_role)', null::text, 'false', 
         coalesce((select bool_or(has_function_privilege(r,p.oid,'execute'))::text from pg_proc p, unnest(array['anon','authenticated','service_role']) r where p.proname in ('guard_assigned_role_authority','guard_role_scope_row_authority','guard_decision_authority')),'n/a'),
         case when coalesce((select bool_or(has_function_privilege(r,p.oid,'execute')) from pg_proc p, unnest(array['anon','authenticated','service_role']) r where p.proname in ('guard_assigned_role_authority','guard_role_scope_row_authority','guard_decision_authority')),false) then 'FAIL' else 'OK' end),
rows_mig as (
  select 'latest recorded migration', '202611250050', '202611250053', coalesce((select max(version) from supabase_migrations.schema_migrations),'none'),
         case (select max(version) from supabase_migrations.schema_migrations) when '202611250053' then 'STATE_053' when '202611250050' then 'STATE_050' else 'OTHER' end),
rows_snap as (
  select 'suspended members vs snapshots (info)', null::text, null::text,
         (select count(*) from iam.memberships where status='suspended')::text||' suspended, '||(select count(*) from iam.membership_suspension_snapshots)::text||' snapshots', 'INFO')
select * from rows_fn union all select * from rows_trg union all select * from rows_acl union all select * from rows_mig union all select * from rows_snap;
