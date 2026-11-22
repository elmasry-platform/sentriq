$ErrorActionPreference = 'Stop'

$container = @(& docker ps --format '{{.Names}}' | Where-Object { $_ -eq 'supabase_db_sentriq' }) | Select-Object -First 1
if (-not $container) { throw 'The disposable local Supabase database container supabase_db_sentriq is not running.' }

$sql = @'
begin;
create function api.__codex_default_acl_probe() returns integer
language sql security definer set search_path='' as 'select 1';
create function private.__codex_default_acl_probe() returns integer
language sql security definer set search_path='' as 'select 1';

do $$
declare
  v_expected_authenticated text[] := array[
    'api.can_use_feature(uuid, text, text, uuid)',
    'api.create_subscription(uuid, uuid, timestamp with time zone, timestamp with time zone, character, jsonb)',
    'api.create_tenant(text, text, uuid)',
    'api.issue_entitlement_grant(uuid, text, text, uuid, timestamp with time zone, timestamp with time zone, text, text, character, bigint, numeric)',
    'api.list_my_entitlements(uuid)',
    'api.manage_subowner(uuid, boolean)',
    'api.publish_plan(text, integer, text, character, bigint, jsonb)',
    'api.revoke_entitlement_grant(uuid, text)',
    'api.revoke_invitation(uuid, text)',
    'api.set_entitlement_grant_status(uuid, text, text)',
    'api.set_feature_enabled(text, boolean)',
    'api.set_module_enabled(text, boolean)',
    'api.update_subscription_status(uuid, text)',
    'private.can_access_core(uuid, text, uuid, boolean)',
    'private.can_access_hse(uuid, text, uuid, boolean, text, uuid)',
    'private.can_access_tenant(uuid)',
    'private.can_manage_tenant(uuid)',
    'private.can_review_hse(uuid, uuid, uuid, boolean)',
    'private.current_membership_id(uuid)',
    'private.is_platform_operator()',
    'private.is_platform_owner()',
    'private.people_scope_allowed(uuid, uuid, uuid, uuid)',
    'private.phase1_membership(uuid)',
    'private.phase1_permission_allowed(uuid, text, uuid, uuid, boolean, text, uuid)'
  ];
  v_expected_service text[] := array[
    'api.accept_invitation(text, uuid)',
    'api.create_invitation(uuid, text, text, uuid, interval)',
    'api.create_invoice_draft(uuid, text, character, timestamp with time zone, timestamp with time zone)',
    'api.invoice_usage_event(uuid, uuid, text)',
    'api.record_feature_usage(uuid, uuid, text, text, numeric, text, jsonb)',
    'api.set_membership_status(uuid, uuid, text, uuid, text)',
    'private.people_scope_allowed(uuid, uuid, uuid, uuid)',
    'private.phase1_membership(uuid)',
    'private.phase1_permission_allowed(uuid, text, uuid, uuid, boolean, text, uuid)'
  ];
  v_observed_authenticated text[];
  v_observed_service text[];
  v_authenticated_oid oid := 'authenticated'::regrole::oid;
  v_service_oid oid := 'service_role'::regrole::oid;
  v_postgres_oid oid := 'postgres'::regrole::oid;
  v_table_oid oid := 'iam.memberships'::regclass::oid;
begin
  select coalesce(array_agg(s.signature order by s.signature),array[]::text[])
    into v_observed_authenticated
    from (
      select n.nspname||'.'||p.proname||'('||pg_catalog.oidvectortypes(p.proargtypes)||')' as signature
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid=p.pronamespace
       where n.nspname in ('api','private') and p.prosecdef
         and has_function_privilege('authenticated',p.oid,'EXECUTE')
    ) s;
  if v_observed_authenticated<>v_expected_authenticated then
    raise exception 'authenticated SECURITY DEFINER ACL mismatch; observed %, expected %',v_observed_authenticated,v_expected_authenticated;
  end if;

  select coalesce(array_agg(s.signature order by s.signature),array[]::text[])
    into v_observed_service
    from (
      select n.nspname||'.'||p.proname||'('||pg_catalog.oidvectortypes(p.proargtypes)||')' as signature
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid=p.pronamespace
       where n.nspname in ('api','private') and p.prosecdef
         and has_function_privilege('service_role',p.oid,'EXECUTE')
    ) s;
  if v_observed_service<>v_expected_service then
    raise exception 'service_role SECURITY DEFINER ACL mismatch; observed %, expected %',v_observed_service,v_expected_service;
  end if;

  if exists (
    select 1 from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid=p.pronamespace
    where n.nspname in ('api','private') and p.prosecdef
      and (pg_catalog.pg_get_userbyid(p.proowner)<>'postgres' or p.proacl is null
        or not (p.proconfig @> array['search_path=""']))
  ) then
    raise exception 'SECURITY DEFINER routines must have owner=postgres, an explicit ACL, and an empty fixed search_path';
  end if;

  if exists (
    select 1 from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid=p.pronamespace
    cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    where n.nspname in ('api','private') and p.prosecdef
      and a.privilege_type='EXECUTE'
      and (a.grantee=0 or pg_catalog.pg_get_userbyid(a.grantee)='anon'
        or a.grantee not in (p.proowner,v_authenticated_oid,v_service_oid))
  ) then
    raise exception 'SECURITY DEFINER ACL contains PUBLIC, anon, or an unapproved grantee';
  end if;

  if exists (
    select 1 from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid=p.pronamespace
    cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    where n.nspname in ('api','private') and p.prosecdef
      and a.privilege_type='EXECUTE' and a.grantee=v_postgres_oid and a.grantee<>p.proowner
  ) then
    raise exception 'unexpected postgres ACL ownership inconsistency';
  end if;

  if not (select relrowsecurity and relforcerowsecurity from pg_catalog.pg_class where oid=v_table_oid) then
    raise exception 'iam.memberships must keep RLS enabled and forced';
  end if;
  if exists (
    select 1 from pg_catalog.pg_policy pol
    where pol.polrelid=v_table_oid and pol.polcmd in ('a','w','d','*')
  ) then
    raise exception 'iam.memberships has an INSERT, UPDATE, DELETE, or ALL RLS policy';
  end if;
  if exists (
    select 1 from (values ('anon'),('authenticated'),('service_role')) r(role_name)
    where has_any_column_privilege(r.role_name,'iam.memberships','INSERT')
       or has_any_column_privilege(r.role_name,'iam.memberships','UPDATE')
       or has_table_privilege(r.role_name,'iam.memberships','DELETE')
  ) then
    raise exception 'API roles must not write iam.memberships directly at table or column level';
  end if;

  if exists (
    select 1 from pg_catalog.pg_proc p
    where p.proname='__codex_default_acl_probe'
      and p.pronamespace in ('api'::regnamespace,'private'::regnamespace)
      and (p.proowner<>v_postgres_oid or p.proacl is null
        or has_function_privilege('anon',p.oid,'EXECUTE')
        or has_function_privilege('authenticated',p.oid,'EXECUTE')
        or has_function_privilege('service_role',p.oid,'EXECUTE')
        or exists(select 1 from aclexplode(p.proacl) a where a.grantee=0 and a.privilege_type='EXECUTE'))
  ) or (select count(*) from pg_catalog.pg_proc p
         where p.proname='__codex_default_acl_probe'
           and p.pronamespace in ('api'::regnamespace,'private'::regnamespace))<>2 then
    raise exception 'default EXECUTE privileges for new API routines are not safely revoked';
  end if;
end $$;

drop function api.__codex_default_acl_probe();
drop function private.__codex_default_acl_probe();
commit;
select 'PASS: SECURITY DEFINER ownership, empty search_path, explicit ACL allowlists, membership write policy, and future-function defaults verified.';
'@

$captured = $sql | & docker exec -i $container psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres 2>&1
$exitCode = $LASTEXITCODE
$output = $captured -join "`n"
if ($exitCode -ne 0) { throw "Security catalog checks failed: $output" }
if ($output -notmatch 'PASS: SECURITY DEFINER ownership') { throw "Security catalog check success evidence was missing: $output" }
Write-Output $output
