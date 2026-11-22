-- Cache auth.uid() once per statement in the Phase 1 insert/read policies.
-- Authorization predicates and access scope remain unchanged.
begin;

drop policy if exists contractor_org_insert on hse.contractor_organizations;
create policy contractor_org_insert on hse.contractor_organizations
  for insert to authenticated
  with check (
    created_by=(select auth.uid())
    and private.phase1_permission_allowed(tenant_id,'contractors',null,null,true)
  );

drop policy if exists engagement_insert on hse.person_engagements;
create policy engagement_insert on hse.person_engagements
  for insert to authenticated
  with check (
    created_by=(select auth.uid())
    and private.phase1_permission_allowed(tenant_id,'engagements',site_id,org_unit_id,true)
  );

drop policy if exists permission_profile_applications_read on iam.permission_profile_applications;
create policy permission_profile_applications_read on iam.permission_profile_applications
  for select to authenticated
  using (
    applied_by=(select auth.uid())
    or exists(
      select 1
      from iam.memberships m
      where m.tenant_id=iam.permission_profile_applications.tenant_id
        and m.id=private.phase1_membership(tenant_id)
        and m.member_role='company_superadmin'
    )
  );

commit;
