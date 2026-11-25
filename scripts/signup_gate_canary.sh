#!/usr/bin/env bash
# Signup gate canary. Proves the real Auth server calls the Before User Created hook and rejects uninvited signups.
# Needs: API_URL (e.g. http://127.0.0.1:54321 or https://<ref>.supabase.co) and ANON_KEY (public anon key).
# Optional:
#   SUPABASE_ACCESS_TOKEN + PROJECT_REF  also checks the hosted project's hook wiring through the management API.
#   DB_CONTAINER                         disposable local database container: also proves a valid invitation signs up
#                                        (creates a fixture invitation and user, then removes both).
# Never prints keys or tokens. Negative checks create no user: the script fails if one appears to exist.
set -euo pipefail
: "${API_URL:?API_URL is required}" "${ANON_KEY:?ANON_KEY is required}"
fail() { echo "FAIL: $*" >&2; exit 1; }
signup() { # email, json-data -> prints "<http_code> <body>"
  curl -s -o /tmp/signup_canary.out -w '%{http_code}' -X POST "$API_URL/auth/v1/signup" \
    -H "apikey: $ANON_KEY" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"Canary-pass-12345\"$2}"
}
rnd() { head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
E1="canary-none-$(rnd)@example.invalid"; E2="canary-bad-$(rnd)@example.invalid"
code=$(signup "$E1" ''); grep -q signup_requires_valid_invitation /tmp/signup_canary.out || fail "signup without a token was not rejected by the hook (http $code)"
[ "$code" = 403 ] || fail "expected 403 for a signup without a token, got $code"
BAD=$(printf 'a%.0s' $(seq 64))
code=$(signup "$E2" ",\"data\":{\"invitation_token\":\"$BAD\"}"); grep -q signup_requires_valid_invitation /tmp/signup_canary.out || fail "signup with an unknown token was not rejected by the hook (http $code)"
echo "PASS: signup without a token and with an unknown token are rejected by the hook (403)."
if [ -n "${SUPABASE_ACCESS_TOKEN:-}" ] && [ -n "${PROJECT_REF:-}" ]; then
  curl -s "https://api.supabase.com/v1/projects/$PROJECT_REF/config/auth" -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" |
    python3 -c 'import json,sys;d=json.load(sys.stdin);ok=d.get("hook_before_user_created_enabled") is True and d.get("hook_before_user_created_uri")=="pg-functions://postgres/private/before_user_created_hook";print("hosted hook wiring:", "ok" if ok else "MISSING");sys.exit(0 if ok else 1)' || fail "hosted project does not have the hook attached"
fi
if [ -n "${DB_CONTAINER:-}" ]; then
  psql_() { docker exec -i "$DB_CONTAINER" psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres; }
  EV="canary-ok-$(rnd)@example.invalid"
  # Fixtures are removed on every exit path, including a failed check under set -e, so a failed run cannot leave rows behind.
  cleanup_fixtures() { psql_ <<SQL >/dev/null
delete from iam.invitations where tenant_id='00000000-0000-0000-0000-00000000ca02';
delete from core.tenants where id='00000000-0000-0000-0000-00000000ca02';
delete from iam.platform_operators where user_id='00000000-0000-0000-0000-00000000ca01';
delete from auth.users where email in ('$EV','canary-owner@example.invalid');
SQL
  }
  trap 'cleanup_fixtures || echo "WARN: canary fixture cleanup failed" >&2' EXIT
  psql_ <<SQL >/dev/null
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at)
 values('00000000-0000-0000-0000-00000000ca01','authenticated','authenticated','canary-owner@example.invalid','',now(),'{}','{}',now(),now()) on conflict do nothing;
insert into iam.platform_operators(user_id,operator_role,created_by) select '00000000-0000-0000-0000-00000000ca01','owner',null
 where not exists(select 1 from iam.platform_operators where operator_role='owner' and active);
insert into core.tenants(id,name,created_by) values('00000000-0000-0000-0000-00000000ca02','Canary Co','00000000-0000-0000-0000-00000000ca01') on conflict do nothing;
SQL
  INV=$(psql_ <<SQL
select token from private.insert_invitation('00000000-0000-0000-0000-00000000ca02','$EV',null,'employee',interval '1 hour','[]'::jsonb,null,'platform',(select user_id from iam.platform_operators where operator_role='owner' and active limit 1));
SQL
)
  TOK=$(printf '%s' "$INV" | tail -1)
  code=$(signup "$EV" ",\"data\":{\"invitation_token\":\"$TOK\"}")
  [ "$code" = 200 ] || fail "a signup with a valid invitation and the invited email was rejected (http $code)"
  code=$(signup "other-$EV" ",\"data\":{\"invitation_token\":\"$TOK\"}")
  [ "$code" = 403 ] || fail "a valid token with a different email was not rejected (http $code)"
  cleanup_fixtures
  echo "PASS: a valid invitation signs up, a different email with the same token is rejected (fixtures removed)."
fi
