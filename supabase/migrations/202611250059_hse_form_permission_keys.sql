-- 059 (HSE M02): permission keys for form approval and retirement.
-- Catalog only. No iam.roles or role_permissions change: company superadmins get the new keys by the
-- default full access rule, everyone else stays denied until a profile or decision grants them.
-- Publishing a form now needs hse.forms.approve (write) on top of hse.forms.manage. Moving a published form to
-- retired or archived needs hse.forms.retire (write); draft to archived stays on manage. The approver may not be the
-- creator, the last editor or the submitter. Both are checked inside the guards, so direct table writes are covered too.
-- No feature rows and no feature link: the new keys are not tied to a feature, so no tenant loses access.
-- Roll back with supabase/rollbacks/202611250059_hse_form_permission_keys.rollback.sql.

insert into iam.permission_catalog(permission_key,module_key,label,description,enabled,feature_key,supported_actions,supported_scope_kinds,requires_reason,is_sensitive)
values
 ('hse.forms.approve','hse','Approve forms','Approve and publish a form template that was submitted for approval. The approver must not be the creator, the last editor or the submitter.',true,null,'{read,write}','{tenant,site,org_unit,assigned_task}',false,true),
 ('hse.forms.retire','hse','Retire forms','Retire or archive a published form template so it can no longer start new records.',true,null,'{read,write}','{tenant,site,org_unit,assigned_task}',false,true)
on conflict(permission_key) do nothing;

create or replace function private.guard_form_template_write() returns trigger language plpgsql security definer set search_path = '' as $f$
declare v_uid uuid := private.form_session_user(); v_content boolean; v_errs jsonb; v_ok boolean;
begin
  if v_uid is null then return new; end if;
  if tg_op = 'INSERT' then
    if new.status <> 'draft' then raise exception 'form_insert_must_be_draft' using errcode = '23514'; end if;
    new.revision := 1; new.last_edited_by := v_uid; new.submitted_by := null; new.submitted_at := null; new.return_reason := null;
    return new;
  end if;
  v_ok := case old.status
    when 'draft' then new.status in ('draft','in_approval','archived')
    when 'in_approval' then new.status in ('in_approval','draft','published')
    when 'published' then new.status in ('published','draft','retired','archived')
    when 'retired' then new.status in ('retired','draft','archived')
    when 'archived' then new.status in ('archived','draft')
    else false end;
  if not v_ok then raise exception 'form_status_transition_not_allowed' using errcode = '23514', detail = old.status || ' to ' || new.status; end if;
  if old.status = 'published' and new.status in ('retired','archived') and not private.can_access_hse(new.tenant_id, 'hse.forms.retire', null, true) then
    raise exception 'form_retire_not_permitted' using errcode = '42501'; end if;
  v_content := row(new.title, new.category, new.definition, new.languages) is distinct from row(old.title, old.category, old.definition, old.languages);
  if v_content and old.status = 'in_approval' then raise exception 'form_locked_in_approval' using errcode = '23514'; end if;
  if v_content and new.status <> 'draft' then raise exception 'form_content_change_requires_draft' using errcode = '23514'; end if;
  new.revision := case when v_content then old.revision + 1 else old.revision end;
  new.last_edited_by := case when v_content then v_uid else old.last_edited_by end;
  new.submitted_by := old.submitted_by; new.submitted_at := old.submitted_at;
  if old.status = 'draft' and new.status = 'in_approval' then
    if nullif(btrim(coalesce(new.change_note, '')), '') is null then raise exception 'form_change_note_required' using errcode = '22023'; end if;
    v_errs := private.validate_form_definition(new.title, new.languages, new.definition);
    if jsonb_array_length(v_errs) > 0 then raise exception 'form_validation_failed' using errcode = '22023', detail = v_errs::text; end if;
    new.submitted_by := v_uid; new.submitted_at := now(); new.return_reason := null;
  elsif old.status = 'in_approval' and new.status = 'draft' then
    if nullif(btrim(coalesce(new.return_reason, '')), '') is null then raise exception 'form_return_reason_required' using errcode = '23514'; end if;
    new.submitted_by := null; new.submitted_at := null;
  elsif old.status = 'in_approval' and new.status = 'published' then
    if not exists (select 1 from hse.form_versions v where v.template_id = new.id and v.approved_at = now() and v.approved_by = v_uid) then
      raise exception 'form_publish_requires_approval' using errcode = '42501'; end if;
  end if;
  return new;
end $f$;
revoke all on function private.guard_form_template_write() from public, anon, authenticated;

create or replace function private.guard_form_version_insert() returns trigger language plpgsql security definer set search_path = '' as $f$
declare v_uid uuid := private.form_session_user(); t hse.form_templates; v_errs jsonb;
begin
  if v_uid is null then
    new.snapshot_hash := coalesce(new.snapshot_hash, private.form_hash(new.snapshot));
    return new;
  end if;
  select * into t from hse.form_templates where id = new.template_id and tenant_id = new.tenant_id for update;
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
  if t.status <> 'in_approval' then raise exception 'form_not_in_approval' using errcode = '22023'; end if;
  if not private.can_access_hse(t.tenant_id, 'hse.forms.approve', null, true) then raise exception 'form_approve_not_permitted' using errcode = '42501'; end if;
  if v_uid = t.submitted_by or v_uid = t.last_edited_by or v_uid = t.created_by then raise exception 'form_approver_must_differ_from_author' using errcode = '42501'; end if;
  v_errs := private.validate_form_definition(t.title, t.languages, t.definition);
  if jsonb_array_length(v_errs) > 0 then raise exception 'form_validation_failed' using errcode = '22023', detail = v_errs::text; end if;
  new.version := coalesce((select max(v.version) from hse.form_versions v where v.template_id = t.id), 0) + 1;
  new.snapshot := private.form_snapshot(t.id);
  new.snapshot_hash := private.form_hash(new.snapshot);
  new.change_note := t.change_note; new.submitted_by := t.submitted_by;
  new.approved_by := v_uid; new.approved_at := now(); new.published_by := v_uid;
  return new;
end $f$;
revoke all on function private.guard_form_version_insert() from public, anon, authenticated;
