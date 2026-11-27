-- Rollback of 058: drop the API, guards and helpers, map the new statuses back (in_approval -> draft, retired -> archived),
-- restore the old status check, drop the added columns (their data is lost). Existing published versions and templates stay.
drop function if exists api.form_version_get(uuid, integer);
drop view if exists api.v_form_versions;
drop view if exists api.v_forms;
create view api.v_forms with (security_invoker=true) as
 select id, tenant_id as "workspaceId", title, category, status, revision, definition, owner_membership_id as "ownerMembershipId", updated_at as "updatedAt"
   from hse.form_templates f;
grant select on api.v_forms to authenticated;
drop function if exists api.form_compare_versions(uuid, integer, integer);
drop function if exists api.form_clone(uuid, jsonb);
drop function if exists api.form_set_status(uuid, integer, text, text);
drop function if exists api.form_set_status(uuid, integer, text);
drop function if exists api.form_approve_publish(uuid, integer);
drop function if exists api.form_return_to_draft(uuid, integer, text);
drop function if exists api.form_submit_for_approval(uuid, integer, text);
drop function if exists api.form_save_draft(uuid, integer, jsonb, text, jsonb, text[]);
drop function if exists api.form_create_draft(uuid, jsonb, text, jsonb, text[]);
drop function if exists api.form_validate(uuid, jsonb, text[], jsonb);
drop trigger if exists z_form_status_audit on hse.form_templates;
drop function if exists private.audit_form_status();
drop trigger if exists form_version_published on hse.form_versions;
drop trigger if exists form_version_insert_guard on hse.form_versions;
drop trigger if exists form_template_write_guard on hse.form_templates;
drop function if exists private.form_version_published();
drop function if exists private.guard_form_version_insert();
drop function if exists private.guard_form_template_write();
drop function if exists private.form_hash(jsonb);
drop function if exists private.form_num(text);
drop function if exists private.form_session_user();
drop function if exists private.form_snapshot(uuid);
drop function if exists private.validate_form_definition(jsonb, text[], jsonb);
drop function if exists private.form_runnable_types();
drop function if exists private.form_field_types();
drop function if exists private.form_err(text, text, text);
update hse.form_templates set status = 'draft' where status = 'in_approval';
update hse.form_templates set status = 'archived' where status = 'retired';
alter table hse.form_templates drop constraint if exists form_templates_languages_check;
alter table hse.form_templates drop constraint if exists form_templates_status_check;
alter table hse.form_templates add constraint form_templates_status_check check (status = any (array['draft','published','archived']));
alter table hse.form_templates
  drop column if exists languages, drop column if exists change_note, drop column if exists return_reason, drop column if exists review_due_date,
  drop column if exists is_library, drop column if exists last_edited_by, drop column if exists submitted_by, drop column if exists submitted_at;
alter table hse.form_versions
  drop column if exists snapshot_hash, drop column if exists change_note, drop column if exists submitted_by, drop column if exists approved_by, drop column if exists approved_at;
