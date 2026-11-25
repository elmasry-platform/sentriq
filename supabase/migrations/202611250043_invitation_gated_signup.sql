-- 043: invitation-gated self-registration.
-- Plain PostgreSQL rules. Only the thin hook wrapper at the end is Supabase-specific.
-- Nothing here writes to auth tables or needs a service key.

-- One rule: is there a live invitation for this token AND this email?
-- Mirrors private.accept_invitation_core (same inviter-standing rule), but takes no lock and changes nothing.
create or replace function private.validate_signup_invitation(p_email text,p_token text)
returns boolean language plpgsql stable security definer set search_path='' as $$
declare v_inv iam.invitations%rowtype; v_email text := lower(btrim(coalesce(p_email,'')));
begin
 if p_token is null or length(p_token) not between 32 and 256 or v_email='' then return false; end if;
 select * into v_inv from iam.invitations where token_hash=extensions.digest(p_token,'sha256');
 if not found or v_inv.accepted_at is not null or v_inv.revoked_at is not null
    or now()>=v_inv.expires_at or v_inv.email<>v_email then return false; end if;
 if not exists(select 1 from core.tenants t where t.id=v_inv.tenant_id and t.status='active') then return false; end if;
 return case when v_inv.origin='platform'
   then exists(select 1 from iam.platform_operators o where o.user_id=v_inv.invited_by and o.active)
   else exists(select 1 from iam.memberships i where i.tenant_id=v_inv.tenant_id and i.user_id=v_inv.invited_by
          and i.member_role='company_superadmin' and i.status='active')
        or exists(select 1 from iam.platform_operators o where o.user_id=v_inv.invited_by and o.active) end;
end $$;

-- Anonymous preview for the invitee's page. Reveals only what the link holder needs; one uniform failure.
create or replace function api.preview_invitation(p_token text)
returns table(company_name text,management_level text,invited_email text,invitee_name text,expires_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
declare v_inv iam.invitations%rowtype;
begin
 if p_token is null or length(p_token) not between 32 and 256 then
   raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 select * into v_inv from iam.invitations where token_hash=extensions.digest(p_token,'sha256');
 if not found or not private.validate_signup_invitation(v_inv.email,p_token) then
   raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 return query select t.name,v_inv.intended_level,v_inv.email,v_inv.invitee_name,v_inv.expires_at
   from core.tenants t where t.id=v_inv.tenant_id;
end $$;

-- Signup gate. Event shape: {"user":{"email":..,"user_metadata":{"invitation_token":..}},..}
-- Reject = HTTP 200 body with an error object (a malformed answer would be a 500 and block nothing).
create or replace function private.before_user_created_hook(event jsonb)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
 if private.validate_signup_invitation(event->'user'->>'email',event->'user'->'user_metadata'->>'invitation_token') then
   return '{}'::jsonb; end if;
 return jsonb_build_object('error',jsonb_build_object('http_code',403,'message','signup_requires_valid_invitation'));
exception when others then
 return jsonb_build_object('error',jsonb_build_object('http_code',403,'message','signup_requires_valid_invitation'));
end $$;

revoke all on function private.validate_signup_invitation(text,text),private.before_user_created_hook(jsonb) from public,anon,authenticated,service_role;
revoke all on function api.preview_invitation(text) from public;
-- anon needs schema usage to reach the one anonymous function. No other api function is executable by anon
-- (checked on TEST: 0 of 61); the pgTAP test G15 keeps it that way.
grant usage on schema api to anon;
grant execute on function api.preview_invitation(text) to anon,authenticated;
do $$ begin
 if exists(select 1 from pg_roles where rolname='supabase_auth_admin') then
  grant usage on schema private to supabase_auth_admin;
  grant execute on function private.before_user_created_hook(jsonb) to supabase_auth_admin;
 end if;
end $$;
