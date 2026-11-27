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
