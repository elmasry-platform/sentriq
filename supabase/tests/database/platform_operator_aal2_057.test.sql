-- 057 (F-02): platform operator authority needs an aal2 session when switch iam.platform_security_settings.require_aal2 is on.
-- The test embeds the rollback (to rebuild the old state, because CI applies every migration first) and the migration
-- (checked against the files by scripts/check_057_embed.sh). Rolled back at the end.
begin;
select extensions.plan(66);
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('f0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','a56-'||i||'@example.test',now(),now(),now() from generate_series(1,5) i;
-- u1 owner, u2 sub-owner, u3 company superadmin, u4 employee, u5 stranger (no membership)
select private.bootstrap_platform_owner('f0000000-0000-0000-0000-000000000001');
select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true);
select set_config('request.jwt.claims','',true);
select api.manage_subowner('f0000000-0000-0000-0000-000000000002',true);
insert into core.tenants(id,name,created_by) values ('f1000000-0000-0000-0000-00000000000a','AAL 56','f0000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,email,status) values
 ('f2000000-0000-0000-0000-000000000003','f1000000-0000-0000-0000-00000000000a','f0000000-0000-0000-0000-000000000003','company_superadmin','a56-3@example.test','active'),
 ('f2000000-0000-0000-0000-000000000004','f1000000-0000-0000-0000-00000000000a','f0000000-0000-0000-0000-000000000004','employee','a56-4@example.test','active');

-- BEGIN EMBEDDED 057 ROLLBACK
-- Rollback of 057: restore the previous function bodies, then drop the switch objects.
CREATE OR REPLACE FUNCTION private.is_platform_operator()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active)
$function$;

CREATE OR REPLACE FUNCTION private.is_platform_owner()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active and p.operator_role = 'owner')
$function$;

CREATE OR REPLACE FUNCTION private.platform_permission_allowed(p_key text, p_actor uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 select exists(select 1 from iam.platform_operators o where o.user_id=coalesce(p_actor,private.request_actor_id()) and o.active
  and (o.operator_role='owner'
   or (o.operator_role='subowner' and not exists(select 1 from iam.platform_permission_grants g
        where g.user_id=o.user_id and g.permission_key=p_key and not g.granted))))
$function$;

CREATE OR REPLACE FUNCTION private.operator_decision_actor()
 RETURNS uuid
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v uuid:=nullif(current_setting('sentriq.operator_decision_actor',true),'')::uuid;
begin
 if v is not null and v=auth.uid() and exists(select 1 from iam.platform_operators o where o.user_id=v and o.active)
    and private.platform_permission_allowed('member.permissions',v) then return v; end if;
 return null;
end $function$;

CREATE OR REPLACE FUNCTION api.my_platform_permissions()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_rows jsonb; v_role text;
begin
 select po.operator_role into v_role
   from iam.platform_operators po
  where po.user_id=private.request_actor_id() and po.active;
 if v_role is null then raise exception 'platform_operator_required' using errcode='42501'; end if;
 if v_role = 'owner' then
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',true) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 else
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',private.platform_permission_allowed(c.permission_key,private.request_actor_id())) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 end if;
 return jsonb_build_object('rows',v_rows);
end $function$;


drop function if exists private.set_platform_aal2_required(boolean, text);
drop function if exists private.platform_aal_ok();
drop table if exists iam.platform_security_settings;
drop function if exists private.platform_security_settings_guard();
-- END EMBEDDED 057 ROLLBACK
select extensions.is(to_regclass('iam.platform_security_settings') is null and to_regproc('private.platform_aal_ok') is null, true, 'T01 before state: no switch table, no aal function');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T02 before state: owner with aal1 is an operator (current behaviour)');
reset role;
-- BEGIN EMBEDDED 057
-- 057 (security F-02): platform operator authority requires an aal2 (MFA) session, behind a switch.
-- Switch: iam.platform_security_settings 'require_aal2'. Default OFF, so behaviour is unchanged until a DB admin turns it on.
-- ON: private.is_platform_operator(), private.is_platform_owner(), the operator branch of platform_permission_allowed(),
-- private.operator_decision_actor() and api.my_platform_permissions()
-- need the JWT claim aal = 'aal2'. An aal1 operator session is refused as if it were not an operator
-- (api.my_platform_permissions answers platform_mfa_required so the UI can ask for the second factor).
-- api.set_membership_status() is service_role only and takes the actor as a parameter; the DB cannot see the user's aal there, so the backend must check aal2 first.
-- Not changed: iam.roles, role_permissions, public signup, table grants. Target lookups of another operator are not gated.
-- Turning the switch on or off is a DB-admin action only (no API, no authenticated grant); every change is audited.

create table if not exists iam.platform_security_settings (
  setting_key text primary key check (setting_key = 'require_aal2'),
  enabled boolean not null default false,
  reason text,
  updated_at timestamptz not null default now()
);
alter table iam.platform_security_settings enable row level security;
alter table iam.platform_security_settings force row level security;
revoke all on iam.platform_security_settings from public, anon, authenticated;
insert into iam.platform_security_settings(setting_key, enabled, reason) values ('require_aal2', false, 'default off until operators are enrolled in MFA')
  on conflict (setting_key) do nothing;

create or replace function private.platform_security_settings_guard() returns trigger language plpgsql security definer set search_path = '' as $f$
begin
  if tg_op = 'DELETE' then raise exception 'platform_security_setting_not_deletable' using errcode = '23514'; end if;
  if tg_op = 'UPDATE' then
    new.setting_key := old.setting_key; new.updated_at := now();
    if new.enabled is distinct from old.enabled and (new.reason is not distinct from old.reason or nullif(btrim(coalesce(new.reason, '')), '') is null) then
      raise exception 'platform_security_setting_reason_required' using errcode = '23514'; end if;
  end if;
  return new;
end $f$;
revoke all on function private.platform_security_settings_guard() from public, anon, authenticated;
drop trigger if exists platform_security_settings_guard on iam.platform_security_settings;
drop trigger if exists audit_row_change on iam.platform_security_settings;
create trigger platform_security_settings_guard before update or delete on iam.platform_security_settings
  for each row execute function private.platform_security_settings_guard();
create trigger audit_row_change after insert or update or delete on iam.platform_security_settings
  for each row execute function private.audit_row_change();

create or replace function private.platform_aal_ok() returns boolean language plpgsql stable security definer set search_path = '' as $f$
begin
  if not coalesce((select s.enabled from iam.platform_security_settings s where s.setting_key = 'require_aal2'), false) then
    return true;
  end if;
  return coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'aal', '') = 'aal2';
exception when others then
  return false; -- switch on and the claim cannot be read: fail closed
end $f$;
revoke all on function private.platform_aal_ok() from public, anon, authenticated;

-- DB-admin only. Example: select private.set_platform_aal2_required(true, 'operators enrolled, checked 2026-..');
create or replace function private.set_platform_aal2_required(p_enabled boolean, p_reason text) returns void language sql security definer set search_path = '' as $f$
  update iam.platform_security_settings set enabled = p_enabled, reason = p_reason where setting_key = 'require_aal2';
$f$;
revoke all on function private.set_platform_aal2_required(boolean, text) from public, anon, authenticated;

CREATE OR REPLACE FUNCTION private.is_platform_operator()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active)
    and private.platform_aal_ok()
$function$;

CREATE OR REPLACE FUNCTION private.is_platform_owner()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active and p.operator_role = 'owner')
    and private.platform_aal_ok()
$function$;

CREATE OR REPLACE FUNCTION private.platform_permission_allowed(p_key text, p_actor uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 select exists(select 1 from iam.platform_operators o where o.user_id=coalesce(p_actor,private.request_actor_id()) and o.active
  and (o.operator_role='owner'
   or (o.operator_role='subowner' and not exists(select 1 from iam.platform_permission_grants g
        where g.user_id=o.user_id and g.permission_key=p_key and not g.granted))))
   and (p_actor is distinct from private.request_actor_id() and p_actor is not null or private.platform_aal_ok())
$function$;

CREATE OR REPLACE FUNCTION private.operator_decision_actor()
 RETURNS uuid
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v uuid:=nullif(current_setting('sentriq.operator_decision_actor',true),'')::uuid;
begin
 if v is not null and v=auth.uid() and private.platform_aal_ok() and exists(select 1 from iam.platform_operators o where o.user_id=v and o.active)
    and private.platform_permission_allowed('member.permissions',v) then return v; end if;
 return null;
end $function$;

CREATE OR REPLACE FUNCTION api.my_platform_permissions()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_rows jsonb; v_role text;
begin
 select po.operator_role into v_role
   from iam.platform_operators po
  where po.user_id=private.request_actor_id() and po.active;
 if v_role is null then raise exception 'platform_operator_required' using errcode='42501'; end if;
 if not private.platform_aal_ok() then raise exception 'platform_mfa_required' using errcode='42501'; end if;
 if v_role = 'owner' then
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',true) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 else
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',private.platform_permission_allowed(c.permission_key,private.request_actor_id())) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 end if;
 return jsonb_build_object('rows',v_rows);
end $function$;
-- END EMBEDDED 057
select extensions.is((select enabled from iam.platform_security_settings where setting_key='require_aal2'), false, 'T03 switch defaults to OFF');
select extensions.is((select count(*)::int from iam.platform_security_settings), 1, 'T04 exactly one switch row');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T05 OFF owner aal1: is_platform_operator true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_owner(), true, 'T06 OFF owner aal1: is_platform_owner true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c$$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T07 OFF owner no aal claim: is_platform_operator true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c$$c$,true); set local role authenticated;
select extensions.is(private.is_platform_owner(), true, 'T08 OFF owner no aal claim: is_platform_owner true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T09 OFF owner aal2: is_platform_operator true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_owner(), true, 'T10 OFF owner aal2: is_platform_owner true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_operator_roster(10,0)$$, 'T11 OFF owner aal1: operator roster works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.my_platform_permissions()$$, 'T12 OFF owner aal1: my_platform_permissions works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_list_companies(10,0)$$, 'T13 OFF sub-owner aal1: list companies works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true);
select extensions.is(private.platform_permission_allowed('company.create'), true, 'T14 OFF owner aal1: permission allowed');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T15 OFF non-operator stays non-operator (aal2 does not make an operator)');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select enabled from iam.platform_security_settings$$, '42501', 'permission denied for table platform_security_settings', 'T16 authenticated cannot read the switch');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.throws_ok($$update iam.platform_security_settings set enabled=true$$, '42501', 'permission denied for table platform_security_settings', 'T17 authenticated owner cannot update the switch');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select private.set_platform_aal2_required(true,'x y z')$$, '42501', 'permission denied for function set_platform_aal2_required', 'T18 authenticated owner cannot call the switch function');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select private.platform_aal_ok()$$, '42501', 'permission denied for function platform_aal_ok', 'T19 authenticated cannot call platform_aal_ok');
reset role;
select extensions.throws_ok($$delete from iam.platform_security_settings$$,'23514','platform_security_setting_not_deletable','T20 switch row cannot be deleted');
select extensions.throws_ok($$update iam.platform_security_settings set enabled=true$$,'23514','platform_security_setting_reason_required','T21 changing the switch needs a reason');
select extensions.throws_ok($$insert into iam.platform_security_settings(setting_key) values ('other')$$,'23514',null,'T22 only the require_aal2 key exists');
select extensions.lives_ok($$select private.set_platform_aal2_required(true,'a56 test')$$,'T23 DB admin turns the switch ON');
select extensions.is((select count(*)::int from audit.events where record_type='iam.platform_security_settings' and action_key='iam.platform_security_settings.update'), 1, 'T24 the change is in the audit trail');
select extensions.is((select summary->'changed_fields'->'enabled'->>'after' from audit.events where record_type='iam.platform_security_settings' and action_key='iam.platform_security_settings.update'), 'true', 'T25 audit row shows enabled=true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T26 ON owner aal1: is_platform_operator false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c$$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T27 ON owner no aal claim: is_platform_operator false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T28 ON owner empty claims object: is_platform_operator false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"AAL2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T29 ON owner aal2 in upper case: is_platform_operator false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":2}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T30 ON owner aal as number 2: is_platform_operator false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c$not json$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), false, 'T31 ON owner malformed claims json: is_platform_operator false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_owner(), false, 'T32 ON owner aal1: is_platform_owner false');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true);
select extensions.is(private.platform_permission_allowed('company.create'), false, 'T33 ON owner aal1: own permission not allowed');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true);
select extensions.is(private.platform_permission_allowed('company.create'), false, 'T34 ON sub-owner aal1: own permission not allowed');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.platform_operator_roster(10,0)$$, '42501', 'platform_read_not_authorized', 'T35 ON owner aal1: operator roster refused');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.platform_list_companies(10,0)$$, '42501', 'platform_read_not_authorized', 'T36 ON owner aal1: list companies refused');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.platform_read_company('f1000000-0000-0000-0000-00000000000a','audit.events',10,0)$$, '42501', 'platform_read_not_authorized', 'T37 ON owner aal1: read company refused');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.my_platform_permissions()$$, '42501', 'platform_mfa_required', 'T38 ON owner aal1: my_platform_permissions says platform_mfa_required');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.my_platform_permissions()$$, '42501', 'platform_operator_required', 'T39 ON non-operator: my_platform_permissions still platform_operator_required');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.manage_subowner('f0000000-0000-0000-0000-000000000002',false)$$, '42501', 'subowner_management_not_allowed', 'T40 ON owner aal1: manage_subowner refused');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.platform_subowner_permissions('f0000000-0000-0000-0000-000000000002')$$, '42501', 'only_owner_can_read_platform_permissions', 'T41 ON owner aal1: sub-owner permissions read refused');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.throws_ok($$select api.create_tenant('Nope 56','x',null)$$, '42501', 'insufficient_privilege', 'T42 ON sub-owner aal1: create_tenant refused');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is((select count(*)::int from core.features), 0, 'T43 ON owner aal1: operator read policy (core.features_read) returns no rows');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T44 ON owner aal2: is_platform_operator true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_owner(), true, 'T45 ON owner aal2: is_platform_owner true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T46 ON sub-owner aal2: is_platform_operator true');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_owner(), false, 'T47 ON sub-owner aal2: is_platform_owner still false (aal does not add rights)');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_operator_roster(10,0)$$, 'T48 ON owner aal2: operator roster works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_list_companies(10,0)$$, 'T49 ON owner aal2: list companies works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_read_company('f1000000-0000-0000-0000-00000000000a','audit.events',10,0)$$, 'T50 ON owner aal2: read company works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.my_platform_permissions()$$, 'T51 ON owner aal2: my_platform_permissions works');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_subowner_permissions('f0000000-0000-0000-0000-000000000002')$$, 'T52 ON owner aal2: sub-owner permissions read works (target lookup)');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true);
select extensions.is(private.platform_permission_allowed('company.create'), true, 'T53 ON owner aal2: permission allowed');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal2"}$c$,true); set local role authenticated;
select extensions.is((select count(*)::int from core.features), 1, 'T54 ON owner aal2: operator read policy (core.features_read) returns the row');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','{"role":"service_role"}',true);
select extensions.is(private.platform_permission_allowed('membership.lifecycle','f0000000-0000-0000-0000-000000000001'), true, 'T55 ON service_role style call (no user in the session, actor as parameter) is not gated by the session aal');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.can_access_tenant('f1000000-0000-0000-0000-00000000000a'), true, 'T56 ON company superadmin aal1: company access unchanged');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims',$c$$c$,true); set local role authenticated;
select extensions.is(private.can_access_tenant('f1000000-0000-0000-0000-00000000000a'), true, 'T57 ON employee with no aal claim: company access unchanged');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims','{"aal":"aal1"}',true); select set_config('sentriq.operator_decision_actor','f0000000-0000-0000-0000-000000000001',true);
select extensions.is(private.operator_decision_actor(), null::uuid, 'X1 ON owner aal1: operator_decision_actor returns null');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims','{"aal":"aal2"}',true); select set_config('sentriq.operator_decision_actor','f0000000-0000-0000-0000-000000000001',true);
select extensions.is(private.operator_decision_actor(), 'f0000000-0000-0000-0000-000000000001'::uuid, 'X2 ON owner aal2: operator_decision_actor returns the actor');
reset role;
select extensions.lives_ok($$select private.set_platform_aal2_required(false,'a56 back off')$$,'T58 DB admin turns the switch OFF');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T59 OFF again: owner aal1 is an operator again');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.lives_ok($$select api.platform_list_companies(10,0)$$, 'T60 OFF again: list companies works at aal1');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims','{"aal":"aal1"}',true); select set_config('sentriq.operator_decision_actor','f0000000-0000-0000-0000-000000000001',true);
select extensions.is(private.operator_decision_actor(), 'f0000000-0000-0000-0000-000000000001'::uuid, 'X3 OFF again: operator_decision_actor returns the actor at aal1');
reset role;
-- BEGIN EMBEDDED 057 ROLLBACK
-- Rollback of 057: restore the previous function bodies, then drop the switch objects.
CREATE OR REPLACE FUNCTION private.is_platform_operator()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active)
$function$;

CREATE OR REPLACE FUNCTION private.is_platform_owner()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active and p.operator_role = 'owner')
$function$;

CREATE OR REPLACE FUNCTION private.platform_permission_allowed(p_key text, p_actor uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 select exists(select 1 from iam.platform_operators o where o.user_id=coalesce(p_actor,private.request_actor_id()) and o.active
  and (o.operator_role='owner'
   or (o.operator_role='subowner' and not exists(select 1 from iam.platform_permission_grants g
        where g.user_id=o.user_id and g.permission_key=p_key and not g.granted))))
$function$;

CREATE OR REPLACE FUNCTION private.operator_decision_actor()
 RETURNS uuid
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v uuid:=nullif(current_setting('sentriq.operator_decision_actor',true),'')::uuid;
begin
 if v is not null and v=auth.uid() and exists(select 1 from iam.platform_operators o where o.user_id=v and o.active)
    and private.platform_permission_allowed('member.permissions',v) then return v; end if;
 return null;
end $function$;

CREATE OR REPLACE FUNCTION api.my_platform_permissions()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_rows jsonb; v_role text;
begin
 select po.operator_role into v_role
   from iam.platform_operators po
  where po.user_id=private.request_actor_id() and po.active;
 if v_role is null then raise exception 'platform_operator_required' using errcode='42501'; end if;
 if v_role = 'owner' then
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',true) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 else
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',private.platform_permission_allowed(c.permission_key,private.request_actor_id())) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 end if;
 return jsonb_build_object('rows',v_rows);
end $function$;


drop function if exists private.set_platform_aal2_required(boolean, text);
drop function if exists private.platform_aal_ok();
drop table if exists iam.platform_security_settings;
drop function if exists private.platform_security_settings_guard();
-- END EMBEDDED 057 ROLLBACK
select extensions.is(to_regclass('iam.platform_security_settings') is null and to_regproc('private.platform_aal_ok') is null and to_regproc('private.set_platform_aal2_required') is null, true, 'T61 rollback removes the switch objects');
select extensions.is((select bool_and(prosrc not ilike '%platform_aal_ok%') from pg_proc where oid in ('private.is_platform_operator()'::regprocedure,'private.is_platform_owner()'::regprocedure,'private.platform_permission_allowed(text,uuid)'::regprocedure,'private.operator_decision_actor()'::regprocedure,'api.my_platform_permissions()'::regprocedure)), true, 'T62 rollback restores all 5 function bodies without the gate');
reset role; select set_config('request.jwt.claim.sub','f0000000-0000-0000-0000-000000000001',true); select set_config('request.jwt.claims',$c${"aal":"aal1"}$c$,true); set local role authenticated;
select extensions.is(private.is_platform_operator(), true, 'T63 after rollback: owner aal1 is an operator (old behaviour)');
select * from extensions.finish();
rollback;