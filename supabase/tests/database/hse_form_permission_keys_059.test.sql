-- 059 (HSE M02): permission keys hse.forms.approve and hse.forms.retire, enforcement in the form guards.
-- The test embeds the rollback (to rebuild the old state, because CI applies every migration first) and the migration
-- (checked against the files by scripts/check_059_embed.sh). Needs 058 applied. Rolled back at the end.
begin;
select extensions.plan(23);
grant usage on schema extensions to anon, authenticated, service_role;
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at) select ('e0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','m-'||i||'@example.test',now(),now(),now() from generate_series(1,7) i;
select private.bootstrap_platform_owner('e0000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values ('e1000000-0000-0000-0000-00000000000a','M58','e0000000-0000-0000-0000-000000000001'),('e1000000-0000-0000-0000-00000000000b','M58 other','e0000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,email,status) values
('e2000000-0000-0000-0000-000000000002','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000002','company_superadmin','m-2@example.test','active'),
('e2000000-0000-0000-0000-000000000003','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000003','company_superadmin','m-3@example.test','active'),
('e2000000-0000-0000-0000-000000000004','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000004','employee','m-4@example.test','active'),
('e2000000-0000-0000-0000-000000000005','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000005','company_superadmin','m-5@example.test','active'),
('e2000000-0000-0000-0000-000000000006','e1000000-0000-0000-0000-00000000000b','e0000000-0000-0000-0000-000000000006','company_superadmin','m-6@example.test','active');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment) values ('e1000000-0000-0000-0000-00000000000a','hse',now()-interval '1 day',now()+interval '30 days','e0000000-0000-0000-0000-000000000001','M58 fixture','complimentary'),('e1000000-0000-0000-0000-00000000000b','hse',now()-interval '1 day',now()+interval '30 days','e0000000-0000-0000-0000-000000000001','M58 fixture','complimentary');
-- u2/u3/u5 company superadmins of A, u4 employee of A, u6 superadmin of B
create function extensions.d59() returns jsonb language sql immutable as $f$ select '{"sections":[{"id":"s1","title":{"en":"S","ar":"ق"},"description":{"en":"","ar":""},"questionIds":["q1"]}],"questions":[{"id":"q1","sectionId":"s1","type":"short_text","title":{"en":"Name","ar":"الاسم"},"required":true,"config":{"maxLength":100,"minLength":0},"conditions":[],"scoring":{"weight":1}}]}'::jsonb $f$;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
create temp table keep59 as select (select md5(coalesce(string_agg(t::text,'|' order by t::text),'')) from iam.role_permissions t) rp, (select md5(coalesce(string_agg(t::text,'|' order by t::text),'')) from iam.roles t) ro;
grant select on keep59 to authenticated;
-- BEGIN EMBEDDED 059 ROLLBACK
-- Rollback for 059. Restores the 058 guards and removes the two catalog rows.
-- Fails (on purpose) if a decision, profile or role version already references a new key: clear those first.
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
  if v_uid = t.submitted_by or v_uid = t.last_edited_by then raise exception 'form_approver_must_differ_from_author' using errcode = '42501'; end if;
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

delete from iam.permission_catalog where permission_key in ('hse.forms.approve','hse.forms.retire');
-- END EMBEDDED 059 ROLLBACK
select extensions.is(((select count(*)::int from iam.permission_catalog where permission_key in ('hse.forms.approve','hse.forms.retire'))::text||'-'||(position('hse.forms.approve' in pg_get_functiondef('private.guard_form_version_insert()'::regprocedure)))::text), '0-0', 'T01 before state (rollback applied): no new keys, guard has no approve check');
reset role;
-- BEGIN EMBEDDED 059
-- 059 (HSE M02): permission keys for form approval and retirement.
-- Catalog only. No iam.roles or role_permissions change: company superadmins get the new keys by the
-- default full access rule, everyone else stays denied until a profile or decision grants them.
-- Publishing a form now needs hse.forms.approve (write) on top of hse.forms.manage. Retiring a published form
-- needs hse.forms.retire (write). Both are checked inside the guards, so direct table writes are covered too.
-- No feature rows and no feature link: the new keys are not tied to a feature, so no tenant loses access.
-- Roll back with supabase/rollbacks/202611250059_hse_form_permission_keys.rollback.sql.

insert into iam.permission_catalog(permission_key,module_key,label,description,enabled,feature_key,supported_actions,supported_scope_kinds,requires_reason,is_sensitive)
values
 ('hse.forms.approve','hse','Approve forms','Approve and publish a form template that was submitted for approval. The approver must not be the author.',true,null,'{read,write}','{tenant,site,org_unit,assigned_task}',false,true),
 ('hse.forms.retire','hse','Retire forms','Retire a published form template so it can no longer start new records.',true,null,'{read,write}','{tenant,site,org_unit,assigned_task}',false,true)
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
  if new.status = 'retired' and old.status <> 'retired' and not private.can_access_hse(new.tenant_id, 'hse.forms.retire', null, true) then
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
  if v_uid = t.submitted_by or v_uid = t.last_edited_by then raise exception 'form_approver_must_differ_from_author' using errcode = '42501'; end if;
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
-- END EMBEDDED 059
reset role;
select extensions.is(((select count(*)::int||'-'||bool_and(enabled)::text||'-'||bool_and(feature_key is null)::text||'-'||bool_and(module_key='hse')::text from iam.permission_catalog where permission_key in ('hse.forms.approve','hse.forms.retire'))), '2-true-true-true', 'P01 both keys are in the catalog, enabled, hse module, not tied to a feature');
select extensions.is(((select count(*)::int from iam.permission_catalog where permission_key in ('hse.forms.approve','hse.forms.retire') and feature_key is not null)), 0, 'P02 no permission key is tied to a feature (no tenant loses access)');
grant execute on function extensions.d59() to authenticated;
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select set_config('t59.x', api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"X","ar":"س"}','Safety',extensions.d59())::text, true);
select api.form_submit_for_approval(current_setting('t59.x')::uuid,1,'x v1');
select set_config('t59.y', api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"Y","ar":"ص"}','Safety',extensions.d59())::text, true);
select api.form_submit_for_approval(current_setting('t59.y')::uuid,1,'y v1');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,granted_by,reason) values ('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000003','hse.forms.approve','deny','tenant','e0000000-0000-0000-0000-000000000001','m59 deny approve'); select set_config('sentriq.migration_runner','off',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t59.x')::uuid,1)$$, '42501', 'form_approve_not_permitted', 'A01 a superadmin with an explicit deny on hse.forms.approve cannot approve');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); delete from iam.member_permission_decisions where membership_id='e2000000-0000-0000-0000-000000000003' and permission_key='hse.forms.approve'; select set_config('sentriq.migration_runner','off',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_approve_publish(current_setting('t59.x')::uuid,1)), 1, 'A02 positive control: the same superadmin without the deny approves (default full access to the new key)');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason) values ('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000004','hse.forms.read','allow','tenant',true,false,'e0000000-0000-0000-0000-000000000001','m59 read'),('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000004','hse.forms.manage','allow','tenant',true,true,'e0000000-0000-0000-0000-000000000001','m59 manage'); select set_config('sentriq.migration_runner','off',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t59.y')::uuid,1)$$, '42501', 'form_approve_not_permitted', 'A03 an employee with forms.manage but without forms.approve cannot approve');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason) values ('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000004','hse.forms.approve','allow','tenant',true,false,'e0000000-0000-0000-0000-000000000001','m59 approve read only'); select set_config('sentriq.migration_runner','off',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t59.y')::uuid,1)$$, '42501', 'form_approve_not_permitted', 'A03b read-only access to forms.approve is not enough to approve (write is needed)');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason) values ('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000004','hse.forms.approve','allow','tenant',true,true,'e0000000-0000-0000-0000-000000000001','m59 approve'); select set_config('sentriq.migration_runner','off',true);
select extensions.is(((select status from hse.form_templates where id=current_setting('t59.y')::uuid)), 'in_approval', 'A04 the refused approval left the template in approval');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_approve_publish(current_setting('t59.y')::uuid,1)), 1, 'A05 positive control: the employee approves once forms.approve is granted');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$insert into hse.form_versions(tenant_id,template_id,version,snapshot,published_by) values ('e1000000-0000-0000-0000-00000000000a',current_setting('t59.y')::uuid,2,'{}','e0000000-0000-0000-0000-000000000004')$$, '22023', 'form_not_in_approval', 'A06 direct version insert on a published template is still refused');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,granted_by,reason) values ('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000005','hse.forms.retire','deny','tenant','e0000000-0000-0000-0000-000000000001','m59 deny retire'); select set_config('sentriq.migration_runner','off',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000005',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_set_status(current_setting('t59.x')::uuid,'retired')$$, '42501', 'form_retire_not_permitted', 'B01 a superadmin with an explicit deny on hse.forms.retire cannot retire');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000005',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$update hse.form_templates set status='retired' where id=current_setting('t59.x')::uuid$$, '42501', 'form_retire_not_permitted', 'B02 a direct table update is refused the same way');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_set_status(current_setting('t59.y')::uuid,'retired')$$, '42501', 'form_retire_not_permitted', 'B03 an employee with manage but without retire cannot retire');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.lives_ok($$select api.form_set_status(current_setting('t59.y')::uuid,'archived')$$, 'B04 archiving needs only forms.manage (retire key is specific to retire)');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.lives_ok($$select api.form_set_status(current_setting('t59.x')::uuid,'retired')$$, 'B05 positive control: a superadmin without the deny retires');
select extensions.is(((select status from hse.form_templates where id=current_setting('t59.x')::uuid)), 'retired', 'B06 template X is retired');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000005',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.lives_ok($$select api.form_set_status(current_setting('t59.x')::uuid,'draft')$$, 'B07 restoring a retired template needs only forms.manage');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select extensions.lives_ok($$update hse.form_templates set status='archived' where id=current_setting('t59.x')::uuid$$, 'B08 database admin path (no user) is not guarded');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000006',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_set_status(current_setting('t59.x')::uuid,'retired')$$, '22023', 'form_not_found', 'B09 a superadmin of another company cannot see or retire it');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select extensions.is(((select (md5(coalesce(string_agg(t::text,'|' order by t::text),'')) = (select rp from keep59))::text||'-'||(select (md5(coalesce(string_agg(t2::text,'|' order by t2::text),'')) = (select ro from keep59))::text from iam.roles t2) from iam.role_permissions t)), 'true-true', 'P04 iam.roles and iam.role_permissions are unchanged by the migration');
select set_config('sentriq.migration_runner','on',true); delete from iam.member_permission_decisions where permission_key in ('hse.forms.approve','hse.forms.retire'); select set_config('sentriq.migration_runner','off',true);
-- BEGIN EMBEDDED 059 ROLLBACK
-- Rollback for 059. Restores the 058 guards and removes the two catalog rows.
-- Fails (on purpose) if a decision, profile or role version already references a new key: clear those first.
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
  if v_uid = t.submitted_by or v_uid = t.last_edited_by then raise exception 'form_approver_must_differ_from_author' using errcode = '42501'; end if;
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

delete from iam.permission_catalog where permission_key in ('hse.forms.approve','hse.forms.retire');
-- END EMBEDDED 059 ROLLBACK
select extensions.is(((select count(*)::int from iam.permission_catalog where permission_key in ('hse.forms.approve','hse.forms.retire'))::text||'-'||(position('hse.forms.approve' in pg_get_functiondef('private.guard_form_version_insert()'::regprocedure)))::text||'-'||(position('hse.forms.retire' in pg_get_functiondef('private.guard_form_template_write()'::regprocedure)))::text), '0-0-0', 'R01 rollback removes the keys and restores both guards');
select extensions.is(((select (md5(coalesce(string_agg(t::text,'|' order by t::text),'')) = (select rp from keep59))::text from iam.role_permissions t)), 'true', 'R02 rollback leaves role_permissions as it was');
select extensions.is(((select count(*)::int from hse.form_versions where template_id in (current_setting('t59.x')::uuid, current_setting('t59.y')::uuid))), 2, 'R03 rollback keeps the published versions');
select * from extensions.finish();
rollback;