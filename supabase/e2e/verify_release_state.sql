-- READ-ONLY release state check. Safe on TEST or production (SELECT only, no writes).
-- Returns one row per check. 'state_050' = expected right after migration 050, 'state_053' = expected after 051-053.
-- Function hashes are left(md5(pg_get_functiondef(oid)),10), measured on a replay of the repo migrations.
-- pg_get_functiondef output can differ between PostgreSQL MAJOR versions: the hashes were measured on PostgreSQL 16.2 (replay)
-- and are equal on TEST, which runs 17.6, so they were stable across these two majors. Run this against a database of the same major version as the measurement, or treat a hash UNKNOWN on a
-- different major version as 'compare the function text', not as a failure by itself. Only ACL, trigger and count rows are version independent.
-- Rows from 046 to 049 and 045 must be the same before and after 051-053 (they do not change in this release).
-- State 054 rows are only expected after migration 054 (STATE_053 on them before it is normal).
-- State 055 rows are only expected after migration 055 (STATE_054 on them before it is normal).
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
  select 'latest recorded migration', '202611250050', '202611250053 (054, 055 after their release)', coalesce((select max(version) from supabase_migrations.schema_migrations),'none'),
         case (select max(version) from supabase_migrations.schema_migrations) when '202611250055' then 'STATE_055' when '202611250054' then 'STATE_054' when '202611250053' then 'STATE_053' when '202611250050' then 'STATE_050' else 'OTHER' end),
rows_snap as (
  select 'suspended members vs snapshots (info)', null::text, null::text,
         (select count(*) from iam.memberships where status='suspended')::text||' suspended, '||(select count(*) from iam.membership_suspension_snapshots)::text||' snapshots', 'INFO'),
rows_old as (
  select 'function '||o.name, o.h, o.h, a.h, case when a.h is not distinct from o.h then 'OK' else 'UNKNOWN' end
  from (values ('api.confirm_evidence(uuid,uuid)','4c663abae9'),('private.guard_evidence_status()','5dca33977f'),
    ('api.create_company_superadmin_invitation(uuid,text,interval,jsonb,text)','4736ef8387'),
    ('api.set_superadmin_capability_limit(uuid,uuid,text,boolean,boolean,text)','2713c6625c'),
    ('private.guard_superadmin_target_rows()','b87975afcd'),('private.is_company_superadmin_of(uuid)','aacd82e91c'),
    ('private.superadmin_limited(uuid,uuid,text)','9aa0a33415'),('private.superadmin_target_blocked(uuid,uuid)','2791e99132')) o(name,h)
  left join actual a on a.name=o.name),
rows_048 as (
  select '048 trigger a00_superadmin_target_guard on 7 tables', null::text, '7 enabled',
         (select count(*)::text||' enabled' from pg_trigger where tgname='a00_superadmin_target_guard' and tgenabled='O' and not tgisinternal),
         case when (select count(*) from pg_trigger where tgname='a00_superadmin_target_guard' and tgenabled='O' and not tgisinternal)=7 then 'OK' else 'FAIL' end),
rows_047 as (
  select '047 authenticated has no SELECT on core.invoices / core.payments', null::text, 'false,false',
         has_table_privilege('authenticated','core.invoices','select')::text||','||has_table_privilege('authenticated','core.payments','select')::text,
         case when not has_table_privilege('authenticated','core.invoices','select') and not has_table_privilege('authenticated','core.payments','select') then 'OK' else 'FAIL' end),
rows_046 as (
  select '046 api.confirm_evidence: authenticated yes, anon no', null::text, 'true,false',
         has_function_privilege('authenticated','api.confirm_evidence(uuid,uuid)','execute')::text||','||has_function_privilege('anon','api.confirm_evidence(uuid,uuid)','execute')::text,
         case when has_function_privilege('authenticated','api.confirm_evidence(uuid,uuid)','execute') and not has_function_privilege('anon','api.confirm_evidence(uuid,uuid)','execute') then 'OK' else 'FAIL' end),
rows_045 as (
  select '045 invalid indexes (must be 0)', null::text, '0', (select count(*)::text from pg_index where not indisvalid),
         case when (select count(*) from pg_index where not indisvalid)=0 then 'OK' else 'FAIL' end),
rows_050acl as (
  select '050 api.membership_restore_report: authenticated yes, anon no, service_role no', null::text, 'true,false,false',
         has_function_privilege('authenticated','api.membership_restore_report(uuid,uuid)','execute')::text||','||has_function_privilege('anon','api.membership_restore_report(uuid,uuid)','execute')::text||','||has_function_privilege('service_role','api.membership_restore_report(uuid,uuid)','execute')::text,
         case when has_function_privilege('authenticated','api.membership_restore_report(uuid,uuid)','execute') and not has_function_privilege('anon','api.membership_restore_report(uuid,uuid)','execute') and not has_function_privilege('service_role','api.membership_restore_report(uuid,uuid)','execute') then 'OK' else 'FAIL' end),
rows_054 as (
  select r.k, r.h053, r.h054, r.actual,
         case when r.actual is not distinct from r.h054 then 'STATE_054' when r.actual is not distinct from r.h053 then 'STATE_053' else 'UNKNOWN' end
  from (
    select 'function api.company_member_permission_decisions(uuid)' k, '3259cd4cdf' h053, '52459d0a61' h054,
           (select h from actual where name='api.company_member_permission_decisions(uuid)') actual
    union all
    select 'function private.is_active_company_admin(uuid)', null, '3d059cdce5', (select h from actual where name='private.is_active_company_admin(uuid)')
    union all
    select 'policy iam.memberships membership_read (md5 of qual+cmd+permissive)', 'b49260b363', '66b0a2b5a4',
           (select left(md5(pg_get_expr(polqual,polrelid)||polcmd::text||polpermissive::text),10) from pg_policy where polrelid='iam.memberships'::regclass and polname='membership_read')) r),
rows_054acl as (
  select '054 private.is_active_company_admin: authenticated yes, anon no, service_role no', null::text, 'true,false,false',
         coalesce(has_function_privilege('authenticated',to_regprocedure('private.is_active_company_admin(uuid)'),'execute')::text||','||has_function_privilege('anon',to_regprocedure('private.is_active_company_admin(uuid)'),'execute')::text||','||has_function_privilege('service_role',to_regprocedure('private.is_active_company_admin(uuid)'),'execute')::text,'not installed'),
         case when to_regprocedure('private.is_active_company_admin(uuid)') is null then 'STATE_053'
              when has_function_privilege('authenticated',to_regprocedure('private.is_active_company_admin(uuid)'),'execute') and not has_function_privilege('anon',to_regprocedure('private.is_active_company_admin(uuid)'),'execute') and not has_function_privilege('service_role',to_regprocedure('private.is_active_company_admin(uuid)'),'execute') then 'OK' else 'FAIL' end),
rows_055 as (
  select r.k, r.h054, r.h055, r.actual,
         case when r.actual is not distinct from r.h055 then 'STATE_055' when r.actual is not distinct from r.h054 then 'STATE_054' else 'UNKNOWN' end
  from (
    select 'function private.admin_can_read_employee_member(uuid,uuid)' k, null::text h054, '415965337b' h055,
           (select h from actual where name='private.admin_can_read_employee_member(uuid,uuid)') actual
    union all
    select 'policy iam.site_access site_access_read (md5 of qual+cmd+permissive)', '325543db4b', '72a9d7a1c8',
           (select left(md5(pg_get_expr(polqual,polrelid)||polcmd::text||polpermissive::text),10) from pg_policy where polrelid='iam.site_access'::regclass and polname='site_access_read')) r),
rows_055acl as (
  select '055 private.admin_can_read_employee_member: authenticated yes, anon no, service_role no', null::text, 'true,false,false',
         coalesce(has_function_privilege('authenticated',to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)'),'execute')::text||','||has_function_privilege('anon',to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)'),'execute')::text||','||has_function_privilege('service_role',to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)'),'execute')::text,'not installed'),
         case when to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)') is null then 'STATE_054'
              when has_function_privilege('authenticated',to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)'),'execute') and not has_function_privilege('anon',to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)'),'execute') and not has_function_privilege('service_role',to_regprocedure('private.admin_can_read_employee_member(uuid,uuid)'),'execute') then 'OK' else 'FAIL' end),
rows_snaprls as (
  select '050 snapshot table: RLS on, forced, no privileges for anon, authenticated, service_role', null::text, 'on,forced,false,false,false,false',
         c.relrowsecurity::text||','||c.relforcerowsecurity::text||','||has_table_privilege('anon','iam.membership_suspension_snapshots','select')::text||','||has_table_privilege('authenticated','iam.membership_suspension_snapshots','select')::text||','||has_table_privilege('authenticated','iam.membership_suspension_snapshots','insert')::text||','||has_table_privilege('service_role','iam.membership_suspension_snapshots','select')::text,
         case when to_regclass('iam.membership_suspension_snapshots') is null then 'MISSING' when c.relrowsecurity and c.relforcerowsecurity and not has_table_privilege('anon','iam.membership_suspension_snapshots','select') and not has_table_privilege('authenticated','iam.membership_suspension_snapshots','select') and not has_table_privilege('authenticated','iam.membership_suspension_snapshots','insert') and not has_table_privilege('service_role','iam.membership_suspension_snapshots','select') then 'OK' else 'FAIL' end
  from pg_class c where c.oid=to_regclass('iam.membership_suspension_snapshots'))
select * from rows_fn union all select * from rows_trg union all select * from rows_acl union all select * from rows_mig union all select * from rows_snap
union all select * from rows_old union all select * from rows_048 union all select * from rows_047 union all select * from rows_046 union all select * from rows_045 union all select * from rows_050acl union all select * from rows_snaprls union all select * from rows_054 union all select * from rows_054acl union all select * from rows_055 union all select * from rows_055acl;
