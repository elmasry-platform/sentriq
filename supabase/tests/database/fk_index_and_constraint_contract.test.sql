begin;
select extensions.plan(4);
select extensions.is((select count(*)::int from pg_constraint where not convalidated and connamespace::regnamespace::text in ('core','iam','hse','audit')),0,'no NOT VALID constraints in app schemas');
select extensions.is((select count(*)::int from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','p') and n.nspname in ('core','iam','hse','audit') and not (c.relrowsecurity and c.relforcerowsecurity)),0,'every app table has RLS enabled and forced');
select extensions.is((select count(*)::int from pg_constraint c where c.contype='f' and c.connamespace::regnamespace::text in ('core','iam','hse','audit')
  and not exists(select 1 from pg_index i where i.indrelid=c.conrelid and (i.indkey::int2[])[0:array_length(c.conkey,1)-1]=c.conkey)
  and not exists(select 1 from unnest(c.conkey) u join pg_attribute a on a.attrelid=c.conrelid and a.attnum=u
    where a.attname in ('created_by','granted_by','revoked_by','set_by','updated_by','assigned_by','resolved_by','published_by','invited_by','uploaded_by','actor_user_id','changed_by','owner_membership_id'))),0,'every non-audit-user foreign key has a supporting index');
select extensions.is((select count(*)::int from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname in ('api','private','core','iam','hse','audit') and p.prosecdef and (p.proconfig is null or not exists(select 1 from unnest(p.proconfig) c where c like 'search_path=%'))),0,'every SECURITY DEFINER function pins search_path');
select * from extensions.finish();
rollback;
