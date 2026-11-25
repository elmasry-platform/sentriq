-- TEMP, never merge. Prints the md5 of the api+private function catalog and of all non-internal triggers.
begin;
select extensions.plan(1);
select extensions.ok(true,'CATALOG_PRE048 functions_md5='||f||' triggers_md5='||t||' function_count='||fc||' trigger_count='||tc) from (select (select md5(string_agg(pg_get_functiondef(p.oid), '' order by p.oid::regprocedure::text)) from pg_proc p where p.pronamespace in ('api'::regnamespace,'private'::regnamespace) and p.prokind='f'), (select md5(string_agg(tgrelid::regclass::text||tgname||tgenabled::text, ',' order by tgrelid::regclass::text,tgname)) from pg_trigger where not tgisinternal), (select count(*) from pg_proc p where p.pronamespace in ('api'::regnamespace,'private'::regnamespace) and p.prokind='f'), (select count(*) from pg_trigger where not tgisinternal)) x(f,t,fc,tc);
select * from extensions.finish();
rollback;
