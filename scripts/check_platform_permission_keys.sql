-- Guard: every permission key gated through private.platform_permission_allowed(...)
-- anywhere in the api/private schema must be registered in
-- iam.platform_permission_catalog. platform_permission_allowed is fail-open by
-- design (a sub-owner holds every power by default until the owner withdraws
-- one), so a gate on an unregistered key would silently allow every sub-owner
-- AND be invisible in the owner Operators UI. When you add a platform RPC,
-- register its key in the catalog in the same migration.
-- Run: psql "$DATABASE_URL" -f scripts/check_platform_permission_keys.sql
with used_keys as (
  select distinct (regexp_matches(p.prosrc, 'platform_permission_allowed\(\s*''([a-z0-9_.]+)''', 'g'))[1] as permission_key
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname in ('api','private')
)
select u.permission_key,
       case when c.permission_key is null then 'MISSING FROM CATALOG' else 'ok' end as status
from used_keys u
left join iam.platform_permission_catalog c using (permission_key)
order by status desc, u.permission_key;
