-- Company-scoped platform reads must use the audited RPC boundary.
begin;
create policy platform_company_read_audit_boundary on audit.events as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.entitlement_grants as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.invoice_items as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.invoices as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.org_units as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.payments as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.sites as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.subscription_items as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.subscriptions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.tenant_domains as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.tenant_entitlements as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.tenants as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on core.usage_events as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.action_updates as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.contractor_organizations as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.corrective_actions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.engagement_supervisor_notes as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.evidence_files as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.findings as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.follow_ups as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.form_templates as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.form_versions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.inspection_reviews as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.inspections as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.people as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.person_engagement_events as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on hse.person_engagements as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.delegation_envelopes as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.delegation_review_events as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.engagement_supervisors as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.invitations as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.member_permission_decisions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.member_permissions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.membership_permission_profiles as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.membership_role_org_units as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.membership_role_sites as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.membership_roles as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.memberships as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.org_unit_access as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.permission_action_grants as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.permission_profile_applications as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.permission_profile_defaults as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.permission_profile_permissions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.permission_profile_versions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.permission_profiles as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.phase1_role_family_review as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.role_version_permissions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.role_versions as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.roles as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.site_access as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.superadmin_capability_limits as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.superadmin_invitation_limits as restrictive for select to authenticated using(not private.is_platform_operator());
create policy platform_company_read_audit_boundary on iam.task_assignments as restrictive for select to authenticated using(not private.is_platform_operator());
drop policy if exists invitations_insert on iam.invitations;
drop policy if exists invitations_update on iam.invitations;
-- Platform roster is platform data; expose it only through an audited projection.
create or replace function api.platform_operator_roster(p_limit integer default 50,p_offset integer default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb;v_event bigint;
begin
 if not private.is_platform_operator() then raise exception 'platform_read_not_authorized' using errcode='42501';end if;
 if p_limit is null or p_limit not between 1 and 100 or p_offset is null or p_offset not between 0 and 10000 then
  raise exception 'platform_read_page_invalid' using errcode='22023';end if;
 select coalesce(jsonb_agg(to_jsonb(page)),'[]'::jsonb) into v_rows from (
  select user_id,operator_role,active,created_by,created_at,deactivated_at from iam.platform_operators order by user_id limit p_limit offset p_offset) page;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,summary)
 values(null,private.request_actor_id(),'platform','platform.operators.list','iam.platform_operators',
  jsonb_build_object('limit',p_limit,'offset',p_offset,'returned',jsonb_array_length(v_rows))) returning id into v_event;
 return jsonb_build_object('rows',v_rows,'limit',p_limit,'offset',p_offset,'audit_event_id',v_event);
end $$;
revoke all on function api.platform_operator_roster(integer,integer) from public,anon,service_role;
grant execute on function api.platform_operator_roster(integer,integer) to authenticated;
commit;
