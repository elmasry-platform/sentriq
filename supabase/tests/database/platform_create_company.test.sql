begin;
select extensions.plan(8);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000601','authenticated','authenticated','cc-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000602','authenticated','authenticated','cc-sub@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000603','authenticated','authenticated','cc-user@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000601');
insert into iam.platform_operators(user_id,operator_role,created_by)
 values('00000000-0000-0000-0000-000000000602','subowner','00000000-0000-0000-0000-000000000601');
create temporary table c(id uuid);
grant insert,select on table pg_temp.c to authenticated;
select set_config('request.jwt.claim.role','authenticated',true);
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000601',true);
set local role authenticated;
select extensions.lives_ok($$insert into c select api.platform_create_company('  Acme Mining ','Mining')$$,'C1 Owner creates a company');
select extensions.is((select count(*)::int from iam.memberships m join c on c.id=m.tenant_id),0,'C2 no member is created');
select extensions.is((select count(*)::int from audit.events e join c on c.id=e.tenant_id where e.action_key='company.create'),1,'C3 creation is audited');
select extensions.throws_ok($$select api.platform_create_company('acme mining')$$,'23505',null,'C4 duplicate name rejected');
select extensions.throws_ok($$select api.platform_create_company(' ')$$,'22023',null,'C5 empty name rejected');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000602',true);
select extensions.lives_ok($$select api.platform_create_company('Sub Made Co')$$,'C6 Sub-owner with the power creates a company');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000603',true);
select extensions.throws_ok($$select api.platform_create_company('Nope Co')$$,'42501',null,'C7 non-operator denied');
reset role;
select extensions.is((select name from core.tenants where name='Acme Mining'),'Acme Mining','C8 name is trimmed');
select * from extensions.finish();
rollback;
