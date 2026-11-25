begin;
select extensions.plan(15);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000a01','authenticated','authenticated','gs-owner@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000a01');
insert into core.tenants(id,name,created_by) values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','GS Co','00000000-0000-0000-0000-000000000a01');
create temporary table t(label text,id uuid,token text);
grant select on table pg_temp.t to anon;
insert into t select 'ok',invitation_id,token from private.insert_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','New.Person@Example.test','New Person','company_superadmin',interval '1 day','[]'::jsonb,null,'platform','00000000-0000-0000-0000-000000000a01');
insert into t select 'exp',invitation_id,token from private.insert_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','exp@example.test',null,'company_admin',interval '1 day','[]'::jsonb,null,'platform','00000000-0000-0000-0000-000000000a01');
insert into t select 'rev',invitation_id,token from private.insert_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','rev@example.test',null,'company_admin',interval '1 day','[]'::jsonb,null,'platform','00000000-0000-0000-0000-000000000a01');
update iam.invitations set created_at=now()-interval '2 days',expires_at=now()-interval '1 second' where id=(select id from t where label='exp');
update iam.invitations set revoked_at=now(),revoked_by='00000000-0000-0000-0000-000000000a01',revoke_reason='test' where id=(select id from t where label='rev');
select extensions.ok(private.validate_signup_invitation('new.person@example.test',(select token from t where label='ok')),'G1 valid token + email (case-insensitive) passes');
select extensions.ok(not private.validate_signup_invitation('other@example.test',(select token from t where label='ok')),'G2 wrong email fails');
select extensions.ok(not private.validate_signup_invitation('new.person@example.test',repeat('a',64)),'G3 unknown token fails');
select extensions.ok(not private.validate_signup_invitation('exp@example.test',(select token from t where label='exp')),'G4 expired fails');
select extensions.ok(not private.validate_signup_invitation('rev@example.test',(select token from t where label='rev')),'G5 revoked fails');
select extensions.ok(not private.validate_signup_invitation('new.person@example.test',null),'G6 missing token fails');
select extensions.is(private.before_user_created_hook(jsonb_build_object('user',jsonb_build_object('email','new.person@example.test','user_metadata',jsonb_build_object('invitation_token',(select token from t where label='ok'))))),'{}'::jsonb,'G7 hook allows a valid invitation');
select extensions.is(private.before_user_created_hook('{"user":{"email":"x@example.test","user_metadata":{}}}')->'error'->>'http_code','403','G8 hook rejects signup with no token (canary)');
select extensions.is(private.before_user_created_hook('{}')->'error'->>'http_code','403','G9 hook rejects a malformed event');
-- anonymous preview
select set_config('request.jwt.claim.role','anon',true);
set local role anon;
select extensions.is((select company_name||'|'||management_level||'|'||invited_email from api.preview_invitation((select token from t where label='ok'))),'GS Co|company_superadmin|new.person@example.test','G10 anon preview shows company, level, email');
select extensions.throws_ok($$select * from api.preview_invitation('short')$$,'22023',null,'G11 bad token rejected');
select extensions.throws_ok($$select * from api.preview_invitation(repeat('b',64))$$,'22023',null,'G12 unknown token rejected');
select extensions.throws_ok($$select private.validate_signup_invitation('a@b.c',repeat('b',64))$$,'42501',null,'G13 anon cannot call the validator directly');
select extensions.is((select count(*)::int from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='api' and has_function_privilege('anon',p.oid,'execute')),1,'G15 preview_invitation is the only api function anon can run');
reset role;
-- once accepted, the token is dead for signup
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000a02','authenticated','authenticated','new.person@example.test','',now(),'{}','{}',now(),now());
select private.accept_invitation_core((select token from t where label='ok'),'00000000-0000-0000-0000-000000000a02');
select extensions.ok(not private.validate_signup_invitation('new.person@example.test',(select token from t where label='ok')),'G14 accepted token no longer passes');
select * from extensions.finish();
rollback;
