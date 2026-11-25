-- 044: hardening on top of 043 (invitation-gated signup). Plain PostgreSQL, no writes to auth tables.

-- 1. 043 gave anon USAGE on schema api so it can reach api.preview_invitation. From now on a new api function
--    must not become callable by anon by accident: new functions created by postgres in api get no EXECUTE for
--    PUBLIC or anon unless a migration grants it. (security_catalog_checks.ps1 and pgTAP G15 also enforce this.)
alter default privileges for role postgres in schema api revoke execute on functions from public, anon;

-- 2. Monitoring for the invitation token that signup stores in the new user's own metadata (the hook receives it
--    through user_metadata, and the hook cannot strip it). The page removes it after acceptance through the Auth
--    API, which is best effort. This lists accounts whose invitation is spent but still carry the key, without
--    returning the token. It reads auth.users only, changes nothing, and is not callable by API roles.
create or replace function private.spent_signup_tokens_in_user_metadata()
returns table(user_id uuid, invitation_id uuid, invitation_state text)
language sql stable security definer set search_path='' as $$
 select u.id, i.id,
   case when i.accepted_at is not null then 'accepted' when i.revoked_at is not null then 'revoked'
        when now()>=i.expires_at then 'expired' else 'pending' end
 from auth.users u
 join iam.invitations i on i.token_hash=extensions.digest(u.raw_user_meta_data->>'invitation_token','sha256')
 where u.raw_user_meta_data ? 'invitation_token'
   and (i.accepted_at is not null or i.revoked_at is not null or now()>=i.expires_at)
$$;
revoke all on function private.spent_signup_tokens_in_user_metadata() from public,anon,authenticated,service_role;
