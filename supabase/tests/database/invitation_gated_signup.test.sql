begin;
select extensions.plan(26);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000a01','authenticated','authenticated','gs-owner@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000a01');
insert into core.tenants(id,name,created_by) values('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','GS Co','00000000-0000-0000-0000-000000000a01');
create temporary table t(label text,id uuid,token text);
grant select on table pg_temp.t to anon,authenticated;
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
-- padded / mixed-case email in the signup event still matches the stored (trimmed, lowercased) invitation
select extensions.ok(private.validate_signup_invitation('  NEW.PERSON@example.TEST  ',(select token from t where label='ok')),'G16 padded, mixed-case email passes');
select extensions.ok(not private.validate_signup_invitation('new.person@example.test ',(select token from t where label='ok')||'x') ,'G17 altered token fails');
select extensions.ok(not private.validate_signup_invitation('   ',(select token from t where label='ok')),'G18 blank email fails');
-- inactive tenant kills signup
update core.tenants set status='suspended' where id='eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01';
select extensions.ok(not private.validate_signup_invitation('new.person@example.test',(select token from t where label='ok')),'G19 suspended company: signup rejected');
update core.tenants set status='active' where id='eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01';
-- inviter loses standing
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000a03','authenticated','authenticated','gs-sub@example.test','',now(),'{}','{}',now(),now());
insert into iam.platform_operators(user_id,operator_role,created_by) values('00000000-0000-0000-0000-000000000a03','subowner','00000000-0000-0000-0000-000000000a01');
insert into t select 'sub',invitation_id,token from private.insert_invitation('eeeeeeee-eeee-eeee-eeee-eeeeeeee0a01','sub-made@example.test',null,'company_admin',interval '1 day','[]'::jsonb,null,'platform','00000000-0000-0000-0000-000000000a03');
select extensions.ok(private.validate_signup_invitation('sub-made@example.test',(select token from t where label='sub')),'G20 invitation by an active Sub-owner passes');
update iam.platform_operators set active=false,deactivated_at=now() where user_id='00000000-0000-0000-0000-000000000a03';
select extensions.ok(not private.validate_signup_invitation('sub-made@example.test',(select token from t where label='sub')),'G21 inviter deactivated: signup rejected');
-- the hook cannot be called directly by anon or a signed-in user
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000a01',true);
set local role authenticated;
select extensions.throws_ok($$select private.before_user_created_hook('{}')$$,'42501',null,'G22 authenticated cannot call the hook');
select extensions.throws_ok($$select private.validate_signup_invitation('a@b.c',repeat('b',64))$$,'42501',null,'G23 authenticated cannot call the validator');
reset role;
set local role anon;
select extensions.throws_ok($$select private.before_user_created_hook('{}')$$,'42501',null,'G24 anon cannot call the hook');
-- anon cannot read any api table or view
select extensions.is((select count(*)::int from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='api' and c.relkind in ('r','v','m','p','f') and has_table_privilege('anon',c.oid,'select')),0,'G25 anon has no select on any api relation');
reset role;
-- a bare authenticated user (no membership, no operator row) sees only the reference catalogs, nothing tenant-owned
create function pg_temp.vis() returns table(rel text, rls boolean, visible_rows bigint) language plpgsql as $$
declare r record; n bigint;
begin
 for r in select nsp.nspname s, c.relname t, c.relrowsecurity rs from pg_class c join pg_namespace nsp on nsp.oid=c.relnamespace
   where c.relkind in ('r','v','m','p') and nsp.nspname not in ('pg_catalog','information_schema','extensions','supabase_migrations','auth','storage','realtime','vault','graphql','graphql_public','pgsodium','cron','net','pgbouncer','supabase_functions','_realtime','pg_temp','pg_toast')
   and nsp.nspname not like 'pg_temp%' and nsp.nspname not like 'pg_toast%'
   and has_schema_privilege('authenticated',nsp.oid,'usage') and has_table_privilege('authenticated',c.oid,'select') order by 1,2
 loop
  begin execute format('select count(*) from %I.%I',r.s,r.t) into n; rel:=r.s||'.'||r.t; rls:=r.rs; visible_rows:=n; return next;
  exception when others then rel:=r.s||'.'||r.t; rls:=r.rs; visible_rows:=-1; return next; end;
 end loop;
end $$;
grant execute on function pg_temp.vis() to authenticated;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','99999999-9999-9999-9999-999999999999',true);
set local role authenticated;
select extensions.is((select coalesce(string_agg(rel,',' order by rel),'') from pg_temp.vis() where visible_rows<>0),'core.modules,iam.permission_catalog,iam.role_permissions,iam.roles','G26 a user with no membership sees only the four reference catalogs');
reset role;
select set_config('request.jwt.claim.sub','',true), set_config('request.jwt.claim.role','',true);
-- once accepted, the token is dead for signup
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000a02','authenticated','authenticated','new.person@example.test','',now(),'{}','{}',now(),now());
select private.accept_invitation_core((select token from t where label='ok'),'00000000-0000-0000-0000-000000000a02');
select extensions.ok(not private.validate_signup_invitation('new.person@example.test',(select token from t where label='ok')),'G14 accepted token no longer passes');
select * from extensions.finish();
rollback;
