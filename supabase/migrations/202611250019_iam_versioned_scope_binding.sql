-- Versioned assignments validate against their immutable snapshot, never the mutable legacy role.
begin;
create or replace function private.validate_membership_role_scope() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_assignment iam.membership_roles%rowtype; v_scope text; v_member_status text;
begin
 if tg_op='UPDATE' then return new; end if;
 select * into v_assignment from iam.membership_roles mr
  where mr.tenant_id=new.tenant_id and mr.id=new.membership_role_id;
 if not found or v_assignment.revoked_at is not null or v_assignment.starts_at>now()
   or (v_assignment.ends_at is not null and now()>=v_assignment.ends_at) then
   raise exception 'active role assignment required for scope binding' using errcode='23514';
 end if;
 select m.status into v_member_status from iam.memberships m
  where m.tenant_id=v_assignment.tenant_id and m.id=v_assignment.membership_id;
 if v_member_status is distinct from 'active' then
   raise exception 'active membership required for scope binding' using errcode='23514';
 end if;
 v_scope:=case when tg_table_name='membership_role_sites' then 'site' else 'org_unit' end;
 if not ((v_assignment.role_version_id is not null and exists(select 1 from iam.role_version_permissions rp
    where rp.tenant_id=new.tenant_id and rp.role_version_id=v_assignment.role_version_id and rp.scope_kind=v_scope))
   or (v_assignment.role_version_id is null and exists(select 1 from iam.role_permissions rp where rp.role_id=v_assignment.role_id
    and rp.active and rp.scope_kind=v_scope))) then
   raise exception 'role has no permission for this scope kind' using errcode='23514';
 end if;
 return new;
end $$;
commit;
