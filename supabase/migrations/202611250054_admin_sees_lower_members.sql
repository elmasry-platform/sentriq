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
