-- TEMP, never merge.
begin;
select extensions.plan(1);
do $w$ declare f text; t text; fc bigint; tc bigint; begin
 select md5(string_agg(pg_get_functiondef(p.oid), '' order by p.oid::regprocedure::text)), count(*) into f, fc from pg_proc p where p.pronamespace in ('api'::regnamespace,'private'::regnamespace) and p.prokind='f';
 select md5(string_agg(tgrelid::regclass::text||tgname||tgenabled::text, ',' order by tgrelid::regclass::text,tgname)), count(*) into t, tc from pg_trigger where not tgisinternal;
 raise warning 'CATALOG_PRE048 functions_md5=% triggers_md5=% function_count=% trigger_count=%', f, t, fc, tc; end $w$;
select extensions.ok(true,'printed');
select * from extensions.finish();
rollback;
