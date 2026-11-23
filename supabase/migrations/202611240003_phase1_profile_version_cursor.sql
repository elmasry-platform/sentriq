begin;

-- Keep the profile's current_version pointer synchronized with its immutable
-- version history, including versions created by the profile-management API.
create or replace function private.advance_permission_profile_cursor() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 update iam.permission_profiles
   set current_version=greatest(current_version,new.version_no)
   where tenant_id=new.tenant_id and id=new.profile_id;
 return new;
end $$;

create trigger permission_profile_cursor_advance
 after insert on iam.permission_profile_versions
 for each row execute function private.advance_permission_profile_cursor();

revoke all on function private.advance_permission_profile_cursor() from public,anon,authenticated,service_role;

commit;
