-- Rollback of 055: restore the earlier site_access_read policy and drop the helper.
drop policy if exists site_access_read on iam.site_access;
create policy site_access_read on iam.site_access for select to authenticated
 using (private.can_manage_tenant(tenant_id)
        or (exists (select 1 from iam.memberships m
                     where m.id = site_access.membership_id and m.user_id = (select auth.uid()))));
drop function if exists private.admin_can_read_employee_member(uuid, uuid);
