-- Evaluate request identity once per policy statement, not once per row.
begin;
create index if not exists memberships_user_id_idx on iam.memberships(user_id);
alter policy "forms_insert" on "hse"."form_templates" with check (((created_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.forms.manage'::text, NULL::uuid, true)));
alter policy "findings_insert" on "hse"."findings" with check (((created_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.findings.manage'::text, site_id, true)));
alter policy "actions_insert" on "hse"."corrective_actions" with check (((created_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.actions.manage'::text, site_id, true)));
alter policy "versions_insert" on "hse"."form_versions" with check (((published_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.forms.manage'::text, NULL::uuid, true)));
alter policy "reviews_insert" on "hse"."inspection_reviews" with check (((actor_user_id = (select auth.uid())) AND (actor_membership_id = private.current_membership_id(tenant_id)) AND (EXISTS ( SELECT 1
   FROM hse.inspections i
  WHERE ((i.tenant_id = inspection_reviews.tenant_id) AND (i.id = inspection_reviews.inspection_id) AND (i.status = ANY (ARRAY['submitted'::text, 'in_review'::text])) AND (i.current_stage = inspection_reviews.stage) AND (private.can_access_hse(inspection_reviews.tenant_id, 'hse.inspections.review'::text, i.site_id, true, 'review'::text, i.id) OR private.can_access_hse(inspection_reviews.tenant_id, ('hse.inspections.review.'::text || inspection_reviews.stage), i.site_id, true, 'review'::text, i.id)))))));
alter policy "evidence_update" on "hse"."evidence_files" using (((uploaded_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.evidence.upload'::text, site_id, true, linked_record_type, linked_record_id))) with check (((uploaded_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.evidence.upload'::text, site_id, true, linked_record_type, linked_record_id)));
alter policy "evidence_insert" on "hse"."evidence_files" with check (((uploaded_by = (select auth.uid())) AND private.can_access_hse(tenant_id, 'hse.evidence.upload'::text, site_id, true, linked_record_type, linked_record_id)));
alter policy "tenant_domains_insert" on "core"."tenant_domains" with check ((private.is_platform_operator() AND (created_by = (select auth.uid()))));
alter policy "site_access_insert" on "iam"."site_access" with check ((private.can_manage_tenant(tenant_id) AND (granted_by = (select auth.uid()))));
alter policy "site_access_read" on "iam"."site_access" using ((private.can_manage_tenant(tenant_id) OR (EXISTS ( SELECT 1
   FROM iam.memberships m
  WHERE ((m.id = site_access.membership_id) AND (m.user_id = (select auth.uid())))))));
alter policy "task_assignments_insert" on "iam"."task_assignments" with check ((private.can_manage_tenant(tenant_id) AND (assigned_by = (select auth.uid()))));
alter policy "task_assignments_read" on "iam"."task_assignments" using ((private.can_manage_tenant(tenant_id) OR (EXISTS ( SELECT 1
   FROM iam.memberships m
  WHERE ((m.id = task_assignments.membership_id) AND (m.user_id = (select auth.uid())))))));
alter policy "membership_read" on "iam"."memberships" using (((user_id = (select auth.uid())) OR private.can_manage_tenant(tenant_id)));
alter policy "grants_insert" on "core"."entitlement_grants" with check ((private.is_platform_operator() AND (granted_by = (select auth.uid()))));
alter policy "roles_insert" on "iam"."roles" with check (((tenant_id IS NOT NULL) AND private.can_manage_tenant(tenant_id) AND (created_by = (select auth.uid())) AND (NOT protected)));
alter policy "invitations_insert" on "iam"."invitations" with check ((private.can_manage_tenant(tenant_id) AND (invited_by = (select auth.uid()))));
alter policy "membership_roles_insert" on "iam"."membership_roles" with check ((private.can_manage_tenant(tenant_id) AND (granted_by = (select auth.uid()))));
alter policy "org_access_insert" on "iam"."org_unit_access" with check ((private.can_manage_tenant(tenant_id) AND (granted_by = (select auth.uid()))));
alter policy "membership_role_sites_insert" on "iam"."membership_role_sites" with check ((private.can_manage_tenant(tenant_id) AND (granted_by = (select auth.uid()))));
alter policy "membership_role_org_units_insert" on "iam"."membership_role_org_units" with check ((private.can_manage_tenant(tenant_id) AND (granted_by = (select auth.uid()))));
alter policy "people_insert" on "hse"."people" with check (((created_by = (select auth.uid())) AND private.phase1_permission_allowed(tenant_id, 'create_edit'::text, NULL::uuid, NULL::uuid, true)));
commit;
