-- Assignment contents cannot be swapped after grant-time validation.
-- Revoke and create a new assignment to change its role or immutable version.
begin;
create or replace function private.guard_role_assignment_identity() returns trigger
language plpgsql set search_path='' as $$
begin
 if new.tenant_id is distinct from old.tenant_id
  or new.membership_id is distinct from old.membership_id
  or new.role_id is distinct from old.role_id
  or new.role_version_id is distinct from old.role_version_id then
  raise exception 'role_assignment_identity_is_immutable' using errcode='23514';
 end if;
 return new;
end $$;
create trigger a0_role_assignment_identity_guard before update on iam.membership_roles
 for each row execute function private.guard_role_assignment_identity();
revoke all on function private.guard_role_assignment_identity() from public,anon,authenticated,service_role;
commit;
