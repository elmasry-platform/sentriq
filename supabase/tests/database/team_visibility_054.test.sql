-- 054: a company Admin sees only members below them (Employees). Runs the real 054 body inline (embedded copy,
-- checked against the migration file by scripts/check_054_embed.sh). Needs 046-053 or main (050) as base. Rolled back at the end.
begin;
select extensions.plan(20);
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at)
select ('c0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','t-'||i||'@example.test',now(),now(),now() from generate_series(1,11) i;
select private.bootstrap_platform_owner('c0000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values ('c1000000-0000-0000-0000-00000000000a','Team A','c0000000-0000-0000-0000-000000000001'),('c1000000-0000-0000-0000-00000000000b','Team B','c0000000-0000-0000-0000-000000000001');
-- A: u2 superadmin, u3 admin (tested), u4 admin (peer), u5 employee, u6 employee (suspended), u7 employee (invited-like: ended)
-- B: u8 superadmin, u9 admin, u10 employee. u11 = admin in A who is suspended.
insert into iam.memberships(id,tenant_id,user_id,member_role,email,status) values
 ('c2000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000002','company_superadmin','t-2@example.test','active'),
 ('c2000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000003','company_admin','t-3@example.test','active'),
 ('c2000000-0000-0000-0000-000000000004','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000004','company_admin','t-4@example.test','active'),
 ('c2000000-0000-0000-0000-000000000005','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000005','employee','t-5@example.test','active'),
 ('c2000000-0000-0000-0000-000000000006','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000006','employee','t-6@example.test','active'),
 ('c2000000-0000-0000-0000-000000000007','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000007','employee','t-7@example.test','active'),
 ('c2000000-0000-0000-0000-000000000008','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000008','company_superadmin','t-8@example.test','active'),
 ('c2000000-0000-0000-0000-000000000009','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000009','company_admin','t-9@example.test','active'),
 ('c2000000-0000-0000-0000-000000000010','c1000000-0000-0000-0000-00000000000b','c0000000-0000-0000-0000-000000000010','employee','t-10@example.test','active'),
 ('c2000000-0000-0000-0000-000000000011','c1000000-0000-0000-0000-00000000000a','c0000000-0000-0000-0000-000000000011','company_admin','t-11@example.test','active');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment)
select t,'hse',now()-interval '1 day',now()+interval '30 days','c0000000-0000-0000-0000-000000000001','Team fixture entitlement','complimentary' from unnest(array['c1000000-0000-0000-0000-00000000000a'::uuid,'c1000000-0000-0000-0000-00000000000b'::uuid]) t;
-- membership status changes go through the guarded path used by the repo tests
select set_config('sentriq.migration_runner','on',true);
update iam.memberships set status='suspended' where id in ('c2000000-0000-0000-0000-000000000006','c2000000-0000-0000-0000-000000000011');
update iam.memberships set status='ended' where id='c2000000-0000-0000-0000-000000000007';
-- decisions on every A member, granted by the superadmin; the admin u3 also granted one to employee u5 below
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,granted_by,reason) values
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000002','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000002','Team decision on superadmin'),
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000003','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000002','Team decision on admin self'),
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000004','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000002','Team decision on peer admin'),
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000005','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000002','Team decision on employee'),
 ('c1000000-0000-0000-0000-00000000000b','c2000000-0000-0000-0000-000000000010','hse.dashboard.read','allow','tenant',true,'c0000000-0000-0000-0000-000000000008','Team decision other tenant');
select set_config('sentriq.migration_runner','off',true);
select set_config('request.jwt.claim.role','authenticated',true);
create function pg_temp.vis(u uuid) returns text language plpgsql as $f$ begin
 perform set_config('request.jwt.claim.sub',u::text,true);
 return coalesce((select string_agg(role||':'||email,',' order by email) from api.v_memberships),'');
end $f$;
grant execute on function pg_temp.vis(uuid) to authenticated;
create function pg_temp.dec(u uuid, t uuid) returns text language plpgsql as $f$
declare r jsonb; begin
 perform set_config('request.jwt.claim.sub',u::text,true);
 r := api.company_member_permission_decisions(t);
 return coalesce((select string_agg((x->>'membership_id')||'/'||coalesce(x->>'granted_by_email','-'),',' order by x->>'membership_id') from jsonb_array_elements(r->'rows') x),'');
end $f$;
grant execute on function pg_temp.dec(uuid,uuid) to authenticated;
-- BEFORE 054 (positive controls: these show the behavior the change replaces)
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000003'),'company_admin:t-3@example.test','S01 before 054 an admin sees only its own row');
select extensions.ok(position('c2000000-0000-0000-0000-000000000002/t-2@example.test' in pg_temp.dec('c0000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a'))>0,'S02 before 054 the decisions RPC shows an admin the superadmin decision and the superadmin email');
reset role;
-- BEGIN EMBEDDED 054
-- 054: a company Admin sees only members BELOW them (Employees), never the Superadmin or other Admins.
-- Product decision as relayed by Main (not verified by me against the original). Level comes from iam.memberships.member_role only, so a temporary
-- permission, delegation or grant cannot widen what an Admin sees.
-- 1) iam.memberships read policy (feeds api.v_memberships, the Team page): own row, or superadmin (unchanged),
--    or an active company admin of the same tenant reading rows whose member_role is 'employee'.
-- 2) api.company_member_permission_decisions: for a company admin, only rows of employees and self; granted_by_email
--    only when the admin granted it. Superadmin and platform operator: unchanged.
-- Rollback: supabase/rollbacks/202611250054_admin_sees_lower_members.rollback.sql. Plain PostgreSQL. No data change.

create or replace function private.is_active_company_admin(p_tenant_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid()
     and m.member_role='company_admin' and m.status='active' and t.status='active')
$$;
revoke all on function private.is_active_company_admin(uuid) from public, anon;
grant execute on function private.is_active_company_admin(uuid) to authenticated;

drop policy if exists membership_read on iam.memberships;
create policy membership_read on iam.memberships for select to authenticated
 using ((user_id = (select auth.uid()))
        or private.can_manage_tenant(tenant_id)
        or (member_role = 'employee' and private.is_active_company_admin(tenant_id)));

CREATE OR REPLACE FUNCTION api.company_member_permission_decisions(p_tenant_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_rows jsonb; v_actor uuid := private.request_actor_id(); v_event bigint; v_full boolean;
begin
 if p_tenant_id is null
    or not (private.is_platform_operator()
            or exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
                       where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active'
                         and m.member_role in ('company_superadmin','company_admin'))) then
   raise exception 'company_decisions_read_not_authorized' using errcode='42501';
 end if;
 -- 054: operators and company superadmins see every row. A company admin sees only employees (and self).
 v_full := private.is_platform_operator() or private.can_manage_tenant(p_tenant_id);
 select coalesce(jsonb_agg(to_jsonb(page)),'[]'::jsonb) into v_rows from (
   select d.id, d.membership_id, d.permission_key, d.decision, d.can_read, d.can_write,
          d.reason, d.created_at, case when v_full or d.granted_by = v_actor then u.email end as granted_by_email
     from iam.member_permission_decisions d
     left join auth.users u on u.id = d.granted_by
    where d.tenant_id = p_tenant_id and d.status = 'active' and d.scope_kind = 'tenant'
      and (v_full or d.membership_id in (select m.id from iam.memberships m
                                          where m.tenant_id = p_tenant_id
                                            and (m.member_role = 'employee' or m.user_id = v_actor)))
    order by d.created_at desc limit 500) page;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,'tenant','iam.permission_decision.listed','iam.member_permission_decisions',p_tenant_id,
        jsonb_build_object('returned',jsonb_array_length(v_rows))) returning id into v_event;
 return jsonb_build_object('rows',v_rows,'audit_event_id',v_event);
end $function$;
-- END EMBEDDED 054

-- AFTER 054
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000003'),'company_admin:t-3@example.test,employee:t-5@example.test,employee:t-6@example.test,employee:t-7@example.test','T01 admin sees itself and the employees of its tenant (any status), nobody else');
select extensions.is((select count(*) from api.v_memberships where role='company_superadmin')::int,0,'T02 admin sees no superadmin');
select extensions.is((select count(*) from api.v_memberships where role='company_admin' and "id"<>'c0000000-0000-0000-0000-000000000003')::int,0,'T03 admin sees no other admin (u4 and the suspended u11 are hidden)');
select extensions.is((select count(*) from api.v_memberships where "workspaceId"='c1000000-0000-0000-0000-00000000000b')::int,0,'T04 admin sees nothing from another tenant');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000005',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000005'),'employee:t-5@example.test','T05 employee still sees only itself');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.is((select count(*) from api.v_memberships where "workspaceId"='c1000000-0000-0000-0000-00000000000a')::int,7,'T06 superadmin still sees all 7 members of its tenant');
select extensions.is((select count(*) from api.v_memberships where "workspaceId"='c1000000-0000-0000-0000-00000000000b')::int,0,'T07 superadmin still sees nothing from another tenant');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000008',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000008'),'employee:t-10@example.test,company_superadmin:t-8@example.test,company_admin:t-9@example.test','T08 tenant B superadmin sees its own three members');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000009',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000009'),'employee:t-10@example.test,company_admin:t-9@example.test','T09 tenant B admin sees itself and its employee only');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000011',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000011'),'company_admin:t-11@example.test','T10 a suspended admin sees only its own row');
-- temporary permissions must not widen visibility: give u3 an expiring tenant envelope, a decision and a role, then compare
reset role;
select set_config('sentriq.migration_runner','on',true);
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason) values
 ('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000011','hse.dashboard.read','allow','tenant',true,true,'c0000000-0000-0000-0000-000000000002','temp widen attempt');
select set_config('sentriq.migration_runner','off',true);
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select api.create_delegation('c1000000-0000-0000-0000-00000000000a','c2000000-0000-0000-0000-000000000003','tenant',null,null,array['role_assignment'],now(),now()+interval '1 day','Temporary envelope for u3');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000003',true);
set local role authenticated;
select extensions.is(pg_temp.vis('c0000000-0000-0000-0000-000000000003'),'company_admin:t-3@example.test,employee:t-5@example.test,employee:t-6@example.test,employee:t-7@example.test','T11 a temporary delegation does not change what the admin sees');
select extensions.is(pg_temp.dec('c0000000-0000-0000-0000-000000000003','c1000000-0000-0000-0000-00000000000a'),'c2000000-0000-0000-0000-000000000003/-,c2000000-0000-0000-0000-000000000005/-','T12 decisions RPC: admin gets only employee and own rows (no superadmin or peer admin row), granted_by email hidden');
select extensions.is((select count(*) from api.v_memberships where "id"='c0000000-0000-0000-0000-000000000002')::int,0,'T13 still no superadmin after the temporary grants');
select extensions.throws_ok($q$select api.company_member_permission_decisions('c1000000-0000-0000-0000-00000000000b')$q$,'42501','company_decisions_read_not_authorized','T14 admin of A is refused the decisions RPC for tenant B');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000005',true);
set local role authenticated;
select extensions.throws_ok($q$select api.company_member_permission_decisions('c1000000-0000-0000-0000-00000000000a')$q$,'42501','company_decisions_read_not_authorized','T15 employee is refused the decisions RPC');
reset role;
select set_config('request.jwt.claim.sub','c0000000-0000-0000-0000-000000000002',true);
set local role authenticated;
select extensions.is(pg_temp.dec('c0000000-0000-0000-0000-000000000002','c1000000-0000-0000-0000-00000000000a'),'c2000000-0000-0000-0000-000000000002/t-2@example.test,c2000000-0000-0000-0000-000000000003/t-2@example.test,c2000000-0000-0000-0000-000000000004/t-2@example.test,c2000000-0000-0000-0000-000000000005/t-2@example.test,c2000000-0000-0000-0000-000000000011/t-2@example.test','T16 superadmin decisions RPC unchanged: all five rows with the granter email');
reset role;
select extensions.ok(not has_function_privilege('anon','private.is_active_company_admin(uuid)','execute'),'T17 anon cannot execute the new helper');
select extensions.ok((select qual from pg_policies where schemaname='iam' and tablename='memberships' and policyname='membership_read') like '%employee%','T18 membership_read names the employee level');
reset role;
select * from extensions.finish();
rollback;
