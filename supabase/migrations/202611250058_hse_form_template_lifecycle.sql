-- 058 (HSE M01): form template lifecycle, server-side publish validation, immutable hashed versions, version compare.
-- Template status: draft, in_approval, published, retired, archived. Editing a published template makes it a draft again;
-- the published versions stay unchanged and keep being what inspections pin to.
-- Approval: the approver must differ from the person who submitted and from the last editor. The version row is created by the
-- approval path only: the server builds the snapshot from the template, numbers it, hashes it (sha256) and stamps approver and time.
-- Guards apply to user sessions: a user id in the token and the database role set to authenticated. DB admin and service paths without a user are not guarded, like the earlier guards.
-- Permission: existing hse.forms.manage (read: hse.forms.read). Separate approve/retire keys come later with the permission catalog work.
-- Not changed: iam.roles, role_permissions, existing published versions (legacy rows keep a null snapshot_hash).

alter table hse.form_templates
  add column if not exists languages text[] not null default array['en','ar'],
  add column if not exists change_note text,
  add column if not exists return_reason text,
  add column if not exists review_due_date date,
  add column if not exists is_library boolean not null default false,
  add column if not exists last_edited_by uuid,
  add column if not exists submitted_by uuid,
  add column if not exists submitted_at timestamptz;
alter table hse.form_templates drop constraint if exists form_templates_status_check;
alter table hse.form_templates add constraint form_templates_status_check
  check (status = any (array['draft','in_approval','published','retired','archived']));
alter table hse.form_templates drop constraint if exists form_templates_languages_check;
alter table hse.form_templates add constraint form_templates_languages_check
  check (cardinality(languages) between 1 and 2 and languages <@ array['en','ar']);
alter table hse.form_versions
  add column if not exists snapshot_hash text,
  add column if not exists change_note text,
  add column if not exists submitted_by uuid,
  add column if not exists approved_by uuid,
  add column if not exists approved_at timestamptz;

create or replace function private.form_err(p_code text, p_question_id text default null, p_detail text default null) returns jsonb
language sql immutable set search_path = '' as $f$
  select jsonb_strip_nulls(jsonb_build_object('code', p_code, 'question_id', p_question_id, 'detail', p_detail))
$f$;

create or replace function private.form_field_types() returns text[] language sql immutable set search_path = '' as $f$
  select array['short_text','long_text','integer','decimal','date','time','datetime','boolean','single_select','multi_select','reference','user','site','location','photo','file','attestation','signature','instruction','gps','barcode_qr','calculated','repeat_group']
$f$;

-- Types the inspection runner can answer today. The others stay in the builder list but are refused at submit and approval,
-- until the runner defines how to fill them. Add a type here in the same release as its runner support.
create or replace function private.form_runnable_types() returns text[] language sql immutable set search_path = '' as $f$
  select array['short_text','long_text','integer','decimal','date','time','datetime','boolean','single_select','multi_select','photo','file','attestation','signature','instruction','gps','calculated']
$f$;
grant execute on function private.form_runnable_types() to authenticated;

-- Server-side publish check. Returns a jsonb array of {code, question_id?, detail?}; empty array = valid.
-- A subset of the client validateForm (same rules for ids, structure, types, choices, bounds, rules and formulas, cycles, 150 cap);
-- parity with the client is checked with shared fixtures in the submission step (M03).
-- Safe number from config text: digits only, at most 12 digits, else null. Avoids cast overflow on hostile input.
create or replace function private.form_num(p text) returns bigint language sql immutable set search_path = '' as $f$
  select case when p ~ '^\d{1,12}$' then p::bigint end
$f$;
grant execute on function private.form_num(text) to authenticated;

create or replace function private.validate_form_definition(p_title jsonb, p_languages text[], p_definition jsonb) returns jsonb
language plpgsql stable set search_path = '' as $f$
declare
  v_err jsonb := '[]'::jsonb;
  v_secs jsonb; v_qs jsonb; v_q jsonb; v_s jsonb; v_c jsonb; v_ch jsonb;
  v_lang text; v_id text; v_type text; v_n int; v_cfg jsonb; v_qids text[]; v_sids text[];
  v_min numeric; v_max numeric; v_a bigint; v_b bigint; v_rest text; v_ref text; v_cnt int;
  v_ops text[] := array['equals','not_equals','contains','greater_than','less_than','is_empty','is_not_empty'];
  v_effects text[] := array['show','hide','require','require_evidence'];
begin
  if p_languages is null or cardinality(p_languages) < 1 or not (p_languages <@ array['en','ar']) then
    return jsonb_build_array(private.form_err('languages_invalid'));
  end if;
  if octet_length(p_definition::text) > 1048576 then
    return jsonb_build_array(private.form_err('definition_too_large'));
  end if;
  if p_definition is null or jsonb_typeof(p_definition) <> 'object'
     or jsonb_typeof(coalesce(p_definition->'sections', '[]'::jsonb)) <> 'array'
     or jsonb_typeof(coalesce(p_definition->'questions', '[]'::jsonb)) <> 'array' then
    return jsonb_build_array(private.form_err('definition_shape_invalid'));
  end if;
  if jsonb_array_length(coalesce(p_definition->'questions', '[]'::jsonb)) > 300 or jsonb_array_length(coalesce(p_definition->'sections', '[]'::jsonb)) > 100 then
    return jsonb_build_array(private.form_err('too_many_questions'));
  end if;
  v_secs := coalesce(p_definition->'sections', '[]'::jsonb);
  v_qs := coalesce(p_definition->'questions', '[]'::jsonb);
  foreach v_lang in array p_languages loop
    if nullif(btrim(coalesce(p_title->>v_lang, '')), '') is null then v_err := v_err || private.form_err('title_missing_language', null, v_lang); end if;
  end loop;
  if jsonb_array_length(v_secs) < 1 then v_err := v_err || private.form_err('no_sections'); end if;
  select coalesce(array_agg(x->>'id'), '{}') into v_sids from jsonb_array_elements(v_secs) x;
  select coalesce(array_agg(x->>'id'), '{}') into v_qids from jsonb_array_elements(v_qs) x;
  if exists (select 1 from unnest(v_sids) i group by i having count(*) > 1 or i is null) then v_err := v_err || private.form_err('section_ids_not_unique'); end if;
  if exists (select 1 from unnest(v_qids) i group by i having count(*) > 1 or i is null) then v_err := v_err || private.form_err('question_ids_not_unique'); end if;
  select count(*) into v_cnt from jsonb_array_elements(v_qs) x where x->>'type' is distinct from 'instruction';
  if v_cnt < 1 then v_err := v_err || private.form_err('no_answerable_question'); end if;
  if v_cnt > 150 then v_err := v_err || private.form_err('too_many_questions', null, v_cnt::text); end if;

  for v_s in select * from jsonb_array_elements(v_secs) loop
    foreach v_lang in array p_languages loop
      if nullif(btrim(coalesce(v_s->'title'->>v_lang, '')), '') is null then v_err := v_err || private.form_err('section_title_missing_language', null, (v_s->>'id') || ':' || v_lang); end if;
    end loop;
    if jsonb_typeof(coalesce(v_s->'questionIds', '[]'::jsonb)) <> 'array' then v_err := v_err || private.form_err('section_shape_invalid', null, v_s->>'id'); continue; end if;
    for v_id in select jsonb_array_elements_text(coalesce(v_s->'questionIds', '[]'::jsonb)) loop
      if not (v_id = any (v_qids)) then v_err := v_err || private.form_err('section_references_missing_question', v_id);
      elsif (select x->>'sectionId' from jsonb_array_elements(v_qs) x where x->>'id' = v_id limit 1) is distinct from (v_s->>'id') then
        v_err := v_err || private.form_err('question_section_mismatch', v_id); end if;
    end loop;
  end loop;

  for v_q in select * from jsonb_array_elements(v_qs) loop
    v_id := v_q->>'id'; v_type := v_q->>'type'; v_cfg := coalesce(v_q->'config', '{}'::jsonb);
    if not (v_type = any (private.form_field_types())) then v_err := v_err || private.form_err('question_type_invalid', v_id, v_type); continue; end if;
    if not (v_type = any (private.form_runnable_types())) then v_err := v_err || private.form_err('question_type_not_supported', v_id, v_type); end if;
    if not ((v_q->>'sectionId') = any (v_sids)) then v_err := v_err || private.form_err('question_section_missing', v_id);
    elsif not exists (select 1 from jsonb_array_elements(v_secs) s where s->>'id' = v_q->>'sectionId' and coalesce(s->'questionIds', '[]'::jsonb) ? v_id) then
      v_err := v_err || private.form_err('question_not_in_section', v_id); end if;
    foreach v_lang in array p_languages loop
      if nullif(btrim(coalesce(v_q->'title'->>v_lang, '')), '') is null then v_err := v_err || private.form_err('question_title_missing_language', v_id, v_lang); end if;
    end loop;
    if v_type in ('single_select','multi_select') then
      if jsonb_typeof(coalesce(v_cfg->'choices', 'null'::jsonb)) <> 'array' or jsonb_array_length(v_cfg->'choices') < 2 then v_err := v_err || private.form_err('choices_too_few', v_id);
      else
        if exists (select 1 from jsonb_array_elements(v_cfg->'choices') c group by c->>'id' having count(*) > 1 or c->>'id' is null) then v_err := v_err || private.form_err('choice_ids_not_unique', v_id); end if;
        for v_ch in select * from jsonb_array_elements(v_cfg->'choices') loop
          foreach v_lang in array p_languages loop
            if nullif(btrim(coalesce(v_ch->'label'->>v_lang, '')), '') is null then v_err := v_err || private.form_err('choice_label_missing_language', v_id, (v_ch->>'id') || ':' || v_lang); end if;
          end loop;
        end loop;
      end if;
    end if;
    if v_type in ('integer','decimal') then
      begin v_min := nullif(v_cfg->>'min', '')::numeric; v_max := nullif(v_cfg->>'max', '')::numeric;
      exception when others then v_err := v_err || private.form_err('numeric_bounds_invalid', v_id); v_min := null; v_max := null; end;
      if v_min is not null and v_max is not null and v_min > v_max then v_err := v_err || private.form_err('numeric_min_above_max', v_id); end if;
    end if;
    if v_type = 'decimal' and (private.form_num(v_cfg->>'precision') is null or private.form_num(v_cfg->>'precision') > 10) then v_err := v_err || private.form_err('decimal_precision_invalid', v_id); end if;
    if v_type in ('short_text','long_text') then
      v_a := private.form_num(v_cfg->>'maxLength'); v_b := private.form_num(coalesce(nullif(v_cfg->>'minLength', ''), '0'));
      if v_a is null or v_a < 1 or v_b is null or v_b > v_a then v_err := v_err || private.form_err('text_length_invalid', v_id); end if;
    end if;
    if v_type in ('photo','file') then
      v_a := private.form_num(v_cfg->>'maxFiles');
      if v_a is null or v_a < 1 then v_err := v_err || private.form_err('file_count_invalid', v_id); end if;
      v_a := private.form_num(v_cfg->>'maxBytes');
      if v_a is null or v_a < 1 or v_a > (case when v_type = 'photo' then 10485760 else 26214400 end) then v_err := v_err || private.form_err('file_size_limit_invalid', v_id); end if;
    end if;
    if v_type = 'repeat_group' then
      if exists (select 1 from jsonb_array_elements(coalesce(v_cfg->'children', '[]'::jsonb)) c where c->>'type' = 'repeat_group') then v_err := v_err || private.form_err('repeat_group_nested', v_id); end if;
      v_a := private.form_num(coalesce(nullif(v_cfg->>'minRows', ''), '0')); v_b := private.form_num(v_cfg->>'maxRows');
      if v_a is null or v_b is null or v_a > v_b then v_err := v_err || private.form_err('repeat_rows_invalid', v_id); end if;
    end if;
    if v_q->'scoring' is not null and jsonb_typeof(v_q->'scoring') = 'object' and coalesce(v_q->'scoring'->>'weight', '0') !~ '^\d+(\.\d+)?$' then v_err := v_err || private.form_err('score_weight_invalid', v_id); end if;
    if v_type = 'calculated' then
      v_rest := regexp_replace(coalesce(v_cfg->>'formula', ''), '\{\{[^{}]+\}\}', '0', 'g');
      if btrim(coalesce(v_cfg->>'formula', '')) = '' or v_rest !~ '^[0-9\s().+*/-]+$' then v_err := v_err || private.form_err('formula_invalid', v_id); end if;
      for v_ref in select m[1] from regexp_matches(coalesce(v_cfg->>'formula', ''), '\{\{([^{}]+)\}\}', 'g') m loop
        if not (v_ref = any (v_qids)) then v_err := v_err || private.form_err('formula_references_missing_question', v_id, v_ref);
        elsif (select x->>'type' from jsonb_array_elements(v_qs) x where x->>'id' = v_ref limit 1) not in ('integer','decimal','calculated') then v_err := v_err || private.form_err('formula_reference_not_numeric', v_id, v_ref); end if;
      end loop;
    end if;
    if jsonb_typeof(coalesce(v_q->'conditions', '[]'::jsonb)) = 'array' then
      for v_c in select * from jsonb_array_elements(coalesce(v_q->'conditions', '[]'::jsonb)) loop
        if not ((v_c->>'sourceQuestionId') = any (v_qids)) or not ((v_c->>'targetQuestionId') = any (v_qids)) then v_err := v_err || private.form_err('rule_references_missing_question', v_id);
        elsif (v_c->>'sourceQuestionId') = (v_c->>'targetQuestionId') then v_err := v_err || private.form_err('rule_source_equals_target', v_id); end if;
        if not ((v_c->>'operator') = any (v_ops)) then v_err := v_err || private.form_err('rule_operator_invalid', v_id); end if;
        if not ((v_c->>'effect') = any (v_effects)) then v_err := v_err || private.form_err('rule_effect_invalid', v_id); end if;
      end loop;
    end if;
  end loop;

  -- cycles: rules (target depends on source) and formulas (calculated question depends on its references), checked separately
  if exists (
    with recursive e(a, b) as (
      select c->>'targetQuestionId', c->>'sourceQuestionId' from jsonb_array_elements(v_qs) q, jsonb_array_elements(coalesce(q->'conditions', '[]'::jsonb)) c
       where jsonb_typeof(coalesce(q->'conditions', '[]'::jsonb)) = 'array'),
    w(s, cur) as (select a, b from e union select w.s, e.b from w join e on e.a = w.cur)
    select 1 from w where s = cur) then v_err := v_err || private.form_err('rule_cycle'); end if;
  if exists (
    with recursive e(a, b) as (
      select q->>'id', m[1] from jsonb_array_elements(v_qs) q, regexp_matches(coalesce(q->'config'->>'formula', ''), '\{\{([^{}]+)\}\}', 'g') m where q->>'type' = 'calculated'),
    w(s, cur) as (select a, b from e union select w.s, e.b from w join e on e.a = w.cur)
    select 1 from w where s = cur) then v_err := v_err || private.form_err('formula_cycle'); end if;
  return v_err;
end $f$;
revoke all on function private.validate_form_definition(jsonb, text[], jsonb) from public, anon;
grant execute on function private.validate_form_definition(jsonb, text[], jsonb) to authenticated;
-- The validator is a plain (invoker) function: it reads only its arguments. It calls two helpers, so those need the same grant.
grant execute on function private.form_err(text, text, text) to authenticated;
grant execute on function private.form_field_types() to authenticated;

create or replace function private.form_snapshot(p_id uuid) returns jsonb language sql stable security definer set search_path = '' as $f$
  select jsonb_build_object('title', t.title, 'category', t.category, 'languages', to_jsonb(t.languages), 'definition', t.definition,
                            'change_note', t.change_note, 'template_revision', t.revision)
    from hse.form_templates t where t.id = p_id
$f$;
revoke all on function private.form_snapshot(uuid) from public, anon, authenticated;

-- The hash is sha256 over the text form of the snapshot jsonb. Adding or removing a field in private.form_snapshot changes the hash
-- of every new version. Old versions keep their stored hash and snapshot, so they still verify. Change the snapshot shape only with a
-- new migration that records the format change (hash format v1 = title, category, languages, definition, change_note, template_revision).
create or replace function private.form_hash(p_snapshot jsonb) returns text language sql immutable set search_path = '' as $f$
  select encode(sha256(convert_to(p_snapshot::text, 'UTF8')), 'hex')
$f$;
revoke all on function private.form_hash(jsonb) from public, anon;
grant execute on function private.form_hash(jsonb) to authenticated;

-- The caller, only when this is a user session (token user and role authenticated). Admin and service sessions get null.
create or replace function private.form_session_user() returns uuid language sql stable set search_path = '' as $f$
  select case when current_setting('role', true) = 'authenticated' then auth.uid() end
$f$;
revoke all on function private.form_session_user() from public, anon;
grant execute on function private.form_session_user() to authenticated;

-- Template write guard (insert and update). User sessions only.
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
drop trigger if exists form_template_write_guard on hse.form_templates;
create trigger form_template_write_guard before insert or update on hse.form_templates
  for each row execute function private.guard_form_template_write();

-- Version insert guard: the approval path. Builds, numbers and hashes the snapshot on the server.
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
drop trigger if exists form_version_insert_guard on hse.form_versions;
create trigger form_version_insert_guard before insert on hse.form_versions
  for each row execute function private.guard_form_version_insert();

create or replace function private.form_version_published() returns trigger language plpgsql security definer set search_path = '' as $f$
begin
  if private.form_session_user() is not null then update hse.form_templates set status = 'published' where id = new.template_id; end if;
  return null;
end $f$;
revoke all on function private.form_version_published() from public, anon, authenticated;
drop trigger if exists form_version_published on hse.form_versions;
create trigger form_version_published after insert on hse.form_versions
  for each row execute function private.form_version_published();

-- API (security invoker: row level security and the guards above apply to the caller)
create or replace function api.form_validate(p_tenant_id uuid, p_title jsonb, p_languages text[], p_definition jsonb) returns jsonb
language plpgsql stable set search_path = '' as $f$
begin
  if not private.can_access_hse(p_tenant_id, 'hse.forms.read') then raise exception 'form_not_permitted' using errcode = '42501'; end if;
  return private.validate_form_definition(p_title, p_languages, p_definition);
end $f$;

create or replace function api.form_create_draft(p_tenant_id uuid, p_title jsonb, p_category text, p_definition jsonb, p_languages text[] default array['en','ar']) returns uuid
language plpgsql set search_path = '' as $f$
declare v_id uuid := gen_random_uuid(); v_m uuid := private.current_membership_id(p_tenant_id);
begin
  if v_m is null then raise exception 'form_not_found' using errcode = '22023'; end if;
  insert into hse.form_templates(id, tenant_id, title, category, status, revision, definition, languages, owner_membership_id, created_by)
  values (v_id, p_tenant_id, p_title, p_category, 'draft', 1, p_definition, p_languages, v_m, auth.uid());
  return v_id;
end $f$;

create or replace function api.form_save_draft(p_id uuid, p_expected_revision integer, p_title jsonb, p_category text, p_definition jsonb, p_languages text[] default array['en','ar']) returns integer
language plpgsql set search_path = '' as $f$
declare t hse.form_templates; v_rev int;
begin
  select * into t from hse.form_templates where id = p_id for update;
  if not found then
    if exists (select 1 from hse.form_templates where id = p_id) then raise exception 'form_not_permitted' using errcode = '42501'; end if;
    raise exception 'form_not_found' using errcode = '22023';
  end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  if t.status = 'in_approval' then raise exception 'form_locked_in_approval' using errcode = '23514'; end if;
  update hse.form_templates set title = p_title, category = p_category, definition = p_definition, languages = p_languages, status = 'draft'
   where id = p_id returning revision into v_rev;
  return v_rev;
end $f$;

create or replace function api.form_submit_for_approval(p_id uuid, p_expected_revision integer, p_change_note text) returns void
language plpgsql set search_path = '' as $f$
declare t hse.form_templates;
begin
  select * into t from hse.form_templates where id = p_id for update;
  if not found then
    if exists (select 1 from hse.form_templates where id = p_id) then raise exception 'form_not_permitted' using errcode = '42501'; end if;
    raise exception 'form_not_found' using errcode = '22023';
  end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  update hse.form_templates set status = 'in_approval', change_note = p_change_note where id = p_id;
end $f$;

create or replace function api.form_return_to_draft(p_id uuid, p_expected_revision integer, p_reason text) returns void
language plpgsql set search_path = '' as $f$
declare t hse.form_templates;
begin
  select * into t from hse.form_templates where id = p_id for update;
  if not found then
    if exists (select 1 from hse.form_templates where id = p_id) then raise exception 'form_not_permitted' using errcode = '42501'; end if;
    raise exception 'form_not_found' using errcode = '22023';
  end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  update hse.form_templates set status = 'draft', return_reason = p_reason where id = p_id;
end $f$;

create or replace function api.form_approve_publish(p_id uuid, p_expected_revision integer) returns integer
language plpgsql set search_path = '' as $f$
declare t hse.form_templates; v_version int;
begin
  select * into t from hse.form_templates where id = p_id for update;
  if not found then
    if exists (select 1 from hse.form_templates where id = p_id) then raise exception 'form_not_permitted' using errcode = '42501'; end if;
    raise exception 'form_not_found' using errcode = '22023';
  end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  insert into hse.form_versions(tenant_id, template_id, version, snapshot, published_by)
  values (t.tenant_id, t.id, 1, '{}'::jsonb, auth.uid()) returning version into v_version;
  return v_version;
end $f$;

create or replace function api.form_set_status(p_id uuid, p_expected_revision integer, p_status text) returns void
language plpgsql set search_path = '' as $f$
declare t hse.form_templates;
begin
  if p_status not in ('retired','archived','draft') then raise exception 'form_status_transition_not_allowed' using errcode = '23514'; end if;
  select * into t from hse.form_templates where id = p_id for update;
  if not found then
    if exists (select 1 from hse.form_templates where id = p_id) then raise exception 'form_not_permitted' using errcode = '42501'; end if;
    raise exception 'form_not_found' using errcode = '22023';
  end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  update hse.form_templates set status = p_status where id = p_id;
end $f$;

create or replace function api.form_clone(p_id uuid, p_title jsonb default null) returns uuid
language plpgsql set search_path = '' as $f$
declare t hse.form_templates; v_id uuid := gen_random_uuid(); v_m uuid;
begin
  select * into t from hse.form_templates where id = p_id;
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
  v_m := private.current_membership_id(t.tenant_id);
  if v_m is null then raise exception 'form_not_found' using errcode = '22023'; end if;
  insert into hse.form_templates(id, tenant_id, title, category, status, revision, definition, languages, owner_membership_id, created_by)
  values (v_id, t.tenant_id, coalesce(p_title, t.title), t.category, 'draft', 1, t.definition, t.languages, v_m, auth.uid());
  return v_id;
end $f$;

create or replace function api.form_compare_versions(p_id uuid, p_from integer, p_to integer) returns jsonb
language plpgsql stable set search_path = '' as $f$
declare a hse.form_versions; b hse.form_versions; v_added jsonb; v_removed jsonb; v_changed jsonb;
begin
  select * into a from hse.form_versions where template_id = p_id and version = p_from;
  if not found then raise exception 'form_version_not_found' using errcode = '22023'; end if;
  select * into b from hse.form_versions where template_id = p_id and version = p_to;
  if not found then raise exception 'form_version_not_found' using errcode = '22023'; end if;
  with qa as (select x->>'id' id, x q from jsonb_array_elements(coalesce(a.snapshot->'definition'->'questions', '[]'::jsonb)) x),
       qb as (select x->>'id' id, x q from jsonb_array_elements(coalesce(b.snapshot->'definition'->'questions', '[]'::jsonb)) x)
  select coalesce((select jsonb_agg(qb.id order by qb.id) from qb where not exists (select 1 from qa where qa.id = qb.id)), '[]'::jsonb),
         coalesce((select jsonb_agg(qa.id order by qa.id) from qa where not exists (select 1 from qb where qb.id = qa.id)), '[]'::jsonb),
         coalesce((select jsonb_agg(jsonb_build_object('id', qa.id, 'fields', (
              select jsonb_agg(k order by k) from (select k from jsonb_object_keys(qa.q || qb.q) k) ks where qa.q->k is distinct from qb.q->k)) order by qa.id)
            from qa join qb on qb.id = qa.id where qa.q is distinct from qb.q), '[]'::jsonb)
    into v_added, v_removed, v_changed;
  return jsonb_build_object('template_id', p_id, 'from_version', p_from, 'to_version', p_to,
    'hash_from', a.snapshot_hash, 'hash_to', b.snapshot_hash,
    'identical', a.snapshot is not distinct from b.snapshot,
    'title_changed', a.snapshot->'title' is distinct from b.snapshot->'title',
    'sections_changed', a.snapshot->'definition'->'sections' is distinct from b.snapshot->'definition'->'sections',
    'added', v_added, 'removed', v_removed, 'changed', v_changed);
end $f$;

-- Read views for the form builder (security invoker: row level security applies to the caller).
-- New columns are appended to api.v_forms; existing columns keep their names and order.
create or replace view api.v_forms with (security_invoker=true) as
 select f.id, f.tenant_id as "workspaceId", f.title, f.category, f.status, f.revision, f.definition,
        f.owner_membership_id as "ownerMembershipId", f.updated_at as "updatedAt",
        f.languages, f.change_note as "changeNote", f.return_reason as "returnReason", f.submitted_by as "submittedBy",
        f.submitted_at as "submittedAt", f.last_edited_by as "lastEditedBy", f.review_due_date as "reviewDueDate", f.is_library as "isLibrary"
   from hse.form_templates f;
grant select on api.v_forms to authenticated;

-- Version history list. No snapshot body here: use api.form_version_get for one snapshot.
create or replace view api.v_form_versions with (security_invoker=true) as
 select v.id, v.tenant_id as "workspaceId", v.template_id as "templateId", v.version, v.snapshot_hash as "snapshotHash",
        v.change_note as "changeNote", v.submitted_by as "submittedBy", v.approved_by as "approvedBy", v.approved_at as "approvedAt",
        v.published_by as "publishedBy", v.published_at as "publishedAt"
   from hse.form_versions v;
grant select on api.v_form_versions to authenticated;

create or replace function api.form_version_get(p_template_id uuid, p_version integer) returns jsonb
language plpgsql stable set search_path = '' as $f$
declare v_snap jsonb;
begin
  select v.snapshot into v_snap from hse.form_versions v where v.template_id = p_template_id and v.version = p_version;
  if v_snap is null then raise exception 'form_version_not_found' using errcode = '22023'; end if;
  return v_snap;
end $f$;

do $g$
declare r record;
begin
  for r in select p.oid::regprocedure as sig from pg_proc p where p.pronamespace = 'api'::regnamespace
     and p.proname in ('form_validate','form_create_draft','form_save_draft','form_submit_for_approval','form_return_to_draft','form_approve_publish','form_set_status','form_clone','form_compare_versions','form_version_get') loop
    execute format('revoke all on function %s from public, anon, service_role', r.sig);
    execute format('grant execute on function %s to authenticated', r.sig);
  end loop;
end $g$;
