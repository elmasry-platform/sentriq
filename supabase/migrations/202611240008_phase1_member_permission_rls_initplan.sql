-- Keep the Phase 1 direct permission read/insert semantics while caching auth.uid().
begin;

drop policy if exists member_permissions_insert on iam.member_permissions;
create policy member_permissions_insert on iam.member_permissions
  for insert to authenticated
  with check (
    private.can_manage_tenant(tenant_id)
    and granted_by=(select auth.uid())
  );

drop policy if exists member_permissions_read on iam.member_permissions;
create policy member_permissions_read on iam.member_permissions
  for select to authenticated
  using (
    private.can_manage_tenant(tenant_id)
    or exists (
      select 1
      from iam.memberships m
      where m.id=iam.member_permissions.membership_id
        and m.user_id=(select auth.uid())
    )
  );

commit;
