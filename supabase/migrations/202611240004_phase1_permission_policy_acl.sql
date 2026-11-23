begin;

-- Permission configuration is non-secret company metadata. Every read is
-- tenant-bound to an active membership; all writes remain RPC-only.
drop policy if exists permission_profile_defaults_read on iam.permission_profile_defaults;
create policy permission_profile_defaults_read on iam.permission_profile_defaults for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists permission_profiles_read on iam.permission_profiles;
create policy permission_profiles_read on iam.permission_profiles for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists permission_profile_versions_read on iam.permission_profile_versions;
create policy permission_profile_versions_read on iam.permission_profile_versions for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists permission_profile_permissions_read on iam.permission_profile_permissions;
create policy permission_profile_permissions_read on iam.permission_profile_permissions for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);

commit;
