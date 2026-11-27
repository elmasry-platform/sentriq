-- 058 (HSE M01): form template lifecycle, publish validation, hashed immutable versions, compare.
-- The test embeds the rollback (to rebuild the old state, because CI applies every migration first) and the migration
-- (checked against the files by scripts/check_058_embed.sh). Rolled back at the end.
begin;
select extensions.plan(105);
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
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
-- u1 platform owner, u2/u3/u5 company superadmins of A (author, approver, third), u4 employee of A, u6 superadmin of B
create function extensions.d58t() returns text language sql immutable as $f$ select '{"sections":[{"id":"s1","title":{"en":"S","ar":"ق"},"description":{"en":"","ar":""},"questionIds":["q1","q2","q3","q4","q5"]}],"questions":[
{"id":"q1","sectionId":"s1","type":"short_text","title":{"en":"Name","ar":"الاسم"},"required":true,"config":{"maxLength":100,"minLength":0},"conditions":[],"scoring":{"weight":1}},
{"id":"q2","sectionId":"s1","type":"integer","title":{"en":"Count","ar":"العدد"},"config":{"min":0,"max":10},"conditions":[],"scoring":{"weight":1}},
{"id":"q3","sectionId":"s1","type":"single_select","title":{"en":"Ok?","ar":"سليم؟"},"config":{"choices":[{"id":"c1","label":{"en":"Yes","ar":"نعم"},"score":1,"finding":false},{"id":"c2","label":{"en":"No","ar":"لا"},"score":0,"finding":true}]},"conditions":[{"id":"r1","sourceQuestionId":"q2","operator":"greater_than","value":5,"targetQuestionId":"q3","effect":"show"}],"scoring":{"weight":2}},
{"id":"q4","sectionId":"s1","type":"calculated","title":{"en":"Double","ar":"ضعف"},"config":{"formula":"{{q2}}*2","precision":2},"conditions":[],"scoring":{"weight":0}},
{"id":"q5","sectionId":"s1","type":"instruction","title":{"en":"Note","ar":"ملاحظة"},"config":{},"conditions":[],"scoring":{"weight":0}}]}'::text $f$;
create function extensions.d58() returns jsonb language sql immutable as $f$ select extensions.d58t()::jsonb $f$;
create function extensions.v58(d jsonb, langs text[] default array['en','ar'], t jsonb default '{"en":"T","ar":"ت"}') returns text language sql as $f$
  select coalesce(string_agg(distinct e->>'code', ',' order by e->>'code'), '') from jsonb_array_elements(private.validate_form_definition(t, langs, d)) e $f$;
create function extensions.rep58(a text, b text) returns jsonb language sql as $f$ select replace(extensions.d58t(), a, b)::jsonb $f$;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
-- BEGIN EMBEDDED 058 ROLLBACK
-- Rollback of 058: drop the API, guards and helpers, map the new statuses back (in_approval -> draft, retired -> archived),
-- restore the old status check, drop the added columns (their data is lost). Existing published versions and templates stay.
drop function if exists api.form_compare_versions(uuid, integer, integer);
drop function if exists api.form_clone(uuid, jsonb);
drop function if exists api.form_set_status(uuid, text);
drop function if exists api.form_approve_publish(uuid, integer);
drop function if exists api.form_return_to_draft(uuid, text);
drop function if exists api.form_submit_for_approval(uuid, integer, text);
drop function if exists api.form_save_draft(uuid, integer, jsonb, text, jsonb, text[]);
drop function if exists api.form_create_draft(uuid, jsonb, text, jsonb, text[]);
drop function if exists api.form_validate(jsonb, text[], jsonb);
drop trigger if exists form_version_published on hse.form_versions;
drop trigger if exists form_version_insert_guard on hse.form_versions;
drop trigger if exists form_template_write_guard on hse.form_templates;
drop function if exists private.form_version_published();
drop function if exists private.guard_form_version_insert();
drop function if exists private.guard_form_template_write();
drop function if exists private.form_hash(jsonb);
drop function if exists private.form_session_user();
drop function if exists private.form_snapshot(uuid);
drop function if exists private.validate_form_definition(jsonb, text[], jsonb);
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
-- END EMBEDDED 058 ROLLBACK
select extensions.is(((select count(*) from information_schema.columns where table_schema='hse' and table_name='form_templates' and column_name='languages')||'-'||coalesce(to_regprocedure('api.form_save_draft(uuid,integer,jsonb,text,jsonb,text[])')::text,'none')), '0-none', 'T01 before state (rollback applied): no languages column, no form API');
reset role;
-- BEGIN EMBEDDED 058
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

-- Server-side publish check. Returns a jsonb array of {code, question_id?, detail?}; empty array = valid.
-- A subset of the client validateForm (same rules for ids, structure, types, choices, bounds, rules and formulas, cycles, 150 cap);
-- parity with the client is checked with shared fixtures in the submission step (M03).
create or replace function private.validate_form_definition(p_title jsonb, p_languages text[], p_definition jsonb) returns jsonb
language plpgsql stable security definer set search_path = '' as $f$
declare
  v_err jsonb := '[]'::jsonb;
  v_secs jsonb; v_qs jsonb; v_q jsonb; v_s jsonb; v_c jsonb; v_ch jsonb;
  v_lang text; v_id text; v_type text; v_n int; v_cfg jsonb; v_qids text[]; v_sids text[];
  v_min numeric; v_max numeric; v_rest text; v_ref text; v_cnt int;
  v_ops text[] := array['equals','not_equals','contains','greater_than','less_than','is_empty','is_not_empty'];
  v_effects text[] := array['show','hide','require','require_evidence'];
begin
  if p_languages is null or cardinality(p_languages) < 1 or not (p_languages <@ array['en','ar']) then
    return jsonb_build_array(private.form_err('languages_invalid'));
  end if;
  if p_definition is null or jsonb_typeof(p_definition) <> 'object'
     or jsonb_typeof(coalesce(p_definition->'sections', '[]'::jsonb)) <> 'array'
     or jsonb_typeof(coalesce(p_definition->'questions', '[]'::jsonb)) <> 'array' then
    return jsonb_build_array(private.form_err('definition_shape_invalid'));
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
    if v_type = 'decimal' and (coalesce(v_cfg->>'precision', '') !~ '^\d+$' or (v_cfg->>'precision')::int > 10) then v_err := v_err || private.form_err('decimal_precision_invalid', v_id); end if;
    if v_type in ('short_text','long_text') then
      if coalesce(v_cfg->>'maxLength', '') !~ '^\d+$' or coalesce(v_cfg->>'maxLength', '0')::int < 1 or coalesce(v_cfg->>'minLength', '0') !~ '^\d+$'
         or coalesce(v_cfg->>'minLength', '0')::int > coalesce(nullif(v_cfg->>'maxLength', ''), '0')::int then v_err := v_err || private.form_err('text_length_invalid', v_id); end if;
    end if;
    if v_type in ('photo','file') then
      if coalesce(v_cfg->>'maxFiles', '') !~ '^\d+$' or coalesce(v_cfg->>'maxFiles', '0')::int < 1 then v_err := v_err || private.form_err('file_count_invalid', v_id); end if;
      if coalesce(v_cfg->>'maxBytes', '') !~ '^\d+$' or coalesce(v_cfg->>'maxBytes', '0')::bigint < 1
         or coalesce(v_cfg->>'maxBytes', '0')::bigint > (case when v_type = 'photo' then 10485760 else 26214400 end) then v_err := v_err || private.form_err('file_size_limit_invalid', v_id); end if;
    end if;
    if v_type = 'repeat_group' then
      if exists (select 1 from jsonb_array_elements(coalesce(v_cfg->'children', '[]'::jsonb)) c where c->>'type' = 'repeat_group') then v_err := v_err || private.form_err('repeat_group_nested', v_id); end if;
      if coalesce(v_cfg->>'minRows', '0') !~ '^\d+$' or coalesce(v_cfg->>'maxRows', '') !~ '^\d+$' or coalesce(v_cfg->>'minRows', '0')::int > coalesce(nullif(v_cfg->>'maxRows', ''), '0')::int then v_err := v_err || private.form_err('repeat_rows_invalid', v_id); end if;
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

create or replace function private.form_snapshot(p_id uuid) returns jsonb language sql stable security definer set search_path = '' as $f$
  select jsonb_build_object('title', t.title, 'category', t.category, 'languages', to_jsonb(t.languages), 'definition', t.definition,
                            'change_note', t.change_note, 'template_revision', t.revision)
    from hse.form_templates t where t.id = p_id
$f$;
revoke all on function private.form_snapshot(uuid) from public, anon, authenticated;

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
create or replace function api.form_validate(p_title jsonb, p_languages text[], p_definition jsonb) returns jsonb
language sql stable set search_path = '' as $f$ select private.validate_form_definition(p_title, p_languages, p_definition) $f$;

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
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
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
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  update hse.form_templates set status = 'in_approval', change_note = p_change_note where id = p_id;
end $f$;

create or replace function api.form_return_to_draft(p_id uuid, p_reason text) returns void
language plpgsql set search_path = '' as $f$
begin
  update hse.form_templates set status = 'draft', return_reason = p_reason where id = p_id;
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
end $f$;

create or replace function api.form_approve_publish(p_id uuid, p_expected_revision integer) returns integer
language plpgsql set search_path = '' as $f$
declare t hse.form_templates; v_version int;
begin
  select * into t from hse.form_templates where id = p_id for update;
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
  if t.revision <> p_expected_revision then raise exception 'form_revision_conflict' using errcode = '40001'; end if;
  insert into hse.form_versions(tenant_id, template_id, version, snapshot, published_by)
  values (t.tenant_id, t.id, 1, '{}'::jsonb, auth.uid()) returning version into v_version;
  return v_version;
end $f$;

create or replace function api.form_set_status(p_id uuid, p_status text) returns void
language plpgsql set search_path = '' as $f$
begin
  if p_status not in ('retired','archived','draft') then raise exception 'form_status_transition_not_allowed' using errcode = '23514'; end if;
  update hse.form_templates set status = p_status where id = p_id;
  if not found then raise exception 'form_not_found' using errcode = '22023'; end if;
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

do $g$
declare r record;
begin
  for r in select p.oid::regprocedure as sig from pg_proc p where p.pronamespace = 'api'::regnamespace
     and p.proname in ('form_validate','form_create_draft','form_save_draft','form_submit_for_approval','form_return_to_draft','form_approve_publish','form_set_status','form_clone','form_compare_versions') loop
    execute format('revoke all on function %s from public, anon, service_role', r.sig);
    execute format('grant execute on function %s to authenticated', r.sig);
  end loop;
end $g$;
-- END EMBEDDED 058
select extensions.is((extensions.v58(extensions.d58())), '', 'V01 valid definition: no errors');
reset role;
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values ('e5000000-0000-0000-0000-000000000001','e1000000-0000-0000-0000-00000000000a','{"en":"Legacy"}','t','published',1,'{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002');
insert into hse.form_versions(id,tenant_id,template_id,version,snapshot,published_by) values ('e6000000-0000-0000-0000-000000000001','e1000000-0000-0000-0000-00000000000a','e5000000-0000-0000-0000-000000000001',1,'{}','e0000000-0000-0000-0000-000000000002');
select extensions.is(((select snapshot_hash is not null and length(snapshot_hash)=64 from hse.form_versions where id='e6000000-0000-0000-0000-000000000001')), true, 'T02 legacy-style insert without a user still gets a hash (DB admin path unguarded)');
select extensions.is(((select count(*)::int from hse.form_templates where id='e5000000-0000-0000-0000-000000000001' and status='published' and languages=array['en','ar'] and is_library=false)), 1, 'T03 existing rows keep working: defaults for languages and library flag');
reset role;
select extensions.is((extensions.v58(extensions.d58(),array['en','ar'],'{"en":"T"}')), 'title_missing_language', 'V02 form title missing for a declared language (default-language label)');
select extensions.is((extensions.v58(extensions.rep58('"ar":"الاسم"','"ar":" "'))), 'question_title_missing_language', 'V03 question title blank in one language');
select extensions.is((extensions.v58(extensions.rep58('"ar":"ق"','"ar":""'))), 'section_title_missing_language', 'V04 section title missing a language');
select extensions.is((extensions.v58(extensions.rep58('"sourceQuestionId":"q2"','"sourceQuestionId":"qX"'))), 'rule_references_missing_question', 'V05 rule references a deleted question (TB-04)');
select extensions.is((extensions.v58(replace(extensions.d58t(),'"conditions":[],"scoring":{"weight":1}},
{"id":"q3"','"conditions":[{"id":"r2","sourceQuestionId":"q3","operator":"equals","value":"c1","targetQuestionId":"q2","effect":"hide"}],"scoring":{"weight":1}},
{"id":"q3"')::jsonb)), 'rule_cycle', 'V06 circular rule (TB-04)');
select extensions.is((extensions.v58(extensions.rep58('"targetQuestionId":"q3"','"targetQuestionId":"q2"'))), 'rule_cycle,rule_source_equals_target', 'V07 rule with same source and target');
select extensions.is((extensions.v58(extensions.rep58('greater_than','near_to'))), 'rule_operator_invalid', 'V08 unsupported rule operator');
select extensions.is((extensions.v58(extensions.rep58('"effect":"show"','"effect":"explode"'))), 'rule_effect_invalid', 'V09 unsupported rule effect');
select extensions.is((extensions.v58(extensions.rep58(',{"id":"c2","label":{"en":"No","ar":"لا"},"score":0,"finding":true}',''))), 'choices_too_few', 'V10 single select with one choice');
select extensions.is((extensions.v58(extensions.rep58('"id":"c2"','"id":"c1"'))), 'choice_ids_not_unique', 'V11 duplicate choice ids');
select extensions.is((extensions.v58(extensions.rep58('"ar":"نعم"','"ar":""'))), 'choice_label_missing_language', 'V12 choice label missing a language');
select extensions.is((extensions.v58(extensions.rep58('{{q2}}*2','{{q4}}+1'))), 'formula_cycle', 'V13 formula refers to itself');
select extensions.is((extensions.v58(extensions.rep58('{{q2}}*2','{{zz}}*2'))), 'formula_references_missing_question', 'V14 formula refers to a missing question');
select extensions.is((extensions.v58(extensions.rep58('{{q2}}*2','{{q1}}*2'))), 'formula_reference_not_numeric', 'V15 formula refers to a non-numeric question');
select extensions.is((extensions.v58(extensions.rep58('{{q2}}*2','sum({{q2}})'))), 'formula_invalid', 'V16 formula with a function name is refused (arithmetic only)');
select extensions.is((extensions.v58(extensions.rep58('"id":"q5"','"id":"q4"'))), 'question_ids_not_unique,section_references_missing_question', 'V17 duplicate question ids');
select extensions.is((extensions.v58(extensions.rep58('"q5"]','"q5","qZ"]'))), 'section_references_missing_question', 'V18 section lists a missing question');
select extensions.is((extensions.v58(extensions.rep58('"id":"s1"','"id":"s0"'))), 'question_section_mismatch,question_section_missing', 'V19 question sectionId does not match its section');
select extensions.is((extensions.v58(extensions.rep58('"type":"integer"','"type":"hologram"'))), 'formula_reference_not_numeric,question_type_invalid', 'V20 unknown question type');
select extensions.is((extensions.v58('{"sections":[{"id":"s1","title":{"en":"S","ar":"ق"},"questionIds":["i1"]}],"questions":[{"id":"i1","sectionId":"s1","type":"instruction","title":{"en":"N","ar":"ن"},"config":{},"conditions":[]}]}'::jsonb)), 'no_answerable_question', 'V21 only an instruction: no answerable question');
select extensions.is((extensions.v58(extensions.rep58('"min":0,"max":10','"min":20,"max":10'))), 'numeric_min_above_max', 'V22 minimum above maximum');
select extensions.is((extensions.v58(extensions.rep58('"maxLength":100','"maxLength":0'))), 'text_length_invalid', 'V23 text max length below 1');
select extensions.is((extensions.v58('{"sections":[],"questions":[]}'::jsonb)), 'no_answerable_question,no_sections', 'V24 no sections');
select extensions.is((extensions.v58('{"sections":5}'::jsonb)), 'definition_shape_invalid', 'V25 definition shape is wrong');
select extensions.is((extensions.v58(extensions.d58(),array['fr'])), 'languages_invalid', 'V26 unsupported language');
select extensions.is((extensions.v58(jsonb_build_object('sections', jsonb_build_array(jsonb_build_object('id','s1','title','{"en":"S","ar":"ق"}'::jsonb,'questionIds',(select jsonb_agg('k'||i) from generate_series(1,150) i))),'questions',(select jsonb_agg(jsonb_build_object('id','k'||i,'sectionId','s1','type','short_text','title','{"en":"Q","ar":"س"}'::jsonb,'config','{"maxLength":10}'::jsonb,'conditions','[]'::jsonb)) from generate_series(1,150) i)))), '', 'V27 exactly 150 answerable questions is valid');
select extensions.is((extensions.v58(jsonb_build_object('sections', jsonb_build_array(jsonb_build_object('id','s1','title','{"en":"S","ar":"ق"}'::jsonb,'questionIds',(select jsonb_agg('k'||i) from generate_series(1,151) i))),'questions',(select jsonb_agg(jsonb_build_object('id','k'||i,'sectionId','s1','type','short_text','title','{"en":"Q","ar":"س"}'::jsonb,'config','{"maxLength":10}'::jsonb,'conditions','[]'::jsonb)) from generate_series(1,151) i)))), 'too_many_questions', 'V28 151 answerable questions is refused');
select extensions.is((extensions.v58(extensions.d58(),array['en'],'{"en":"T"}')), '', 'V29 English-only template with English labels is valid (Arabic not required when not declared)');
select extensions.is((extensions.v58(extensions.rep58('"maxLength":100','"maxLength":100'),array['en','ar'],'{"en":"T","ar":""}')), 'title_missing_language', 'V30 blank Arabic title is missing');
select extensions.is((extensions.v58(extensions.rep58('"id":"q5","sectionId":"s1","type":"instruction"','"id":"q5","sectionId":"s1","type":"photo"'))), 'file_count_invalid,file_size_limit_invalid', 'V31 photo question without limits is refused');
select extensions.is((extensions.v58(extensions.rep58('"id":"q5","sectionId":"s1","type":"instruction","title":{"en":"Note","ar":"ملاحظة"},"config":{}','"id":"q5","sectionId":"s1","type":"photo","title":{"en":"Note","ar":"ملاحظة"},"config":{"maxFiles":3,"maxBytes":10485760}'))), '', 'V32 photo question at the 10 MB limit is valid');
select extensions.is((extensions.v58(extensions.rep58('"id":"q5","sectionId":"s1","type":"instruction","title":{"en":"Note","ar":"ملاحظة"},"config":{}','"id":"q5","sectionId":"s1","type":"photo","title":{"en":"Note","ar":"ملاحظة"},"config":{"maxFiles":3,"maxBytes":10485761}'))), 'file_size_limit_invalid', 'V33 photo question above 10 MB is refused');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select set_config('t58.a', api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"Fire","ar":"حريق"}','Safety',extensions.d58())::text, true);
select extensions.is(((select status||'-'||revision||'-'||(last_edited_by='e0000000-0000-0000-0000-000000000002')::text||'-'||languages::text from hse.form_templates where id=current_setting('t58.a')::uuid)), 'draft-1-true-{en,ar}', 'L01 create draft: draft, revision 1, last editor is the creator');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"X","ar":"س"}','c','{}')$$, '42501', null, 'L02 employee cannot create a form template');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000006',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_save_draft(current_setting('t58.a')::uuid,1,'{"en":"X","ar":"س"}','c','{}')$$, '22023', 'form_not_found', 'L03 other company cannot see or save the template');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_save_draft(current_setting('t58.a')::uuid,1,'{"en":"Fire","ar":"حريق"}','Safety','{"sections":[],"questions":[]}')), 2, 'L04 save with the right revision returns revision 2');
select extensions.throws_ok($$select api.form_save_draft(current_setting('t58.a')::uuid,1,'{"en":"Fire","ar":"حريق"}','Safety','{}')$$, '40001', 'form_revision_conflict', 'L05 stale revision is refused');
select extensions.is((api.form_save_draft(current_setting('t58.a')::uuid,2,'{"en":"Fire","ar":"حريق"}','Safety','{"sections":[],"questions":[]}')), 2, 'L06 saving the same content does not bump the revision');
select extensions.throws_ok($$select api.form_submit_for_approval(current_setting('t58.a')::uuid,2,'first version')$$, '22023', 'form_validation_failed', 'L07 an incomplete draft can be saved but not submitted');
select api.form_save_draft(current_setting('t58.a')::uuid,2,'{"en":"Fire","ar":"حريق"}','Safety',extensions.d58());
select extensions.throws_ok($$select api.form_submit_for_approval(current_setting('t58.a')::uuid,3,'  ')$$, '22023', 'form_change_note_required', 'L08 submit needs a change note');
select extensions.lives_ok($$select api.form_submit_for_approval(current_setting('t58.a')::uuid,3,'first version')$$, 'L09 valid draft is submitted for approval');
select extensions.is(((select status||'-'||submitted_by::text from hse.form_templates where id=current_setting('t58.a')::uuid)), 'in_approval-e0000000-0000-0000-0000-000000000002', 'L10 status in_approval, submitter recorded');
select extensions.throws_ok($$select api.form_save_draft(current_setting('t58.a')::uuid,3,'{"en":"Fire","ar":"حريق"}','Safety','{}')$$, '23514', 'form_locked_in_approval', 'L11 save is refused while in approval');
select extensions.throws_ok($$update hse.form_templates set definition='{}' where id=current_setting('t58.a')::uuid$$, '23514', 'form_locked_in_approval', 'L12 direct content update is refused while in approval');
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t58.a')::uuid,3)$$, '42501', 'form_approver_must_differ_from_author', 'L13 the author cannot approve own template (TB-05)');
select extensions.throws_ok($$update hse.form_templates set status='published' where id=current_setting('t58.a')::uuid$$, '42501', 'form_publish_requires_approval', 'L14 direct move to published without an approved version is refused');
select extensions.throws_ok($$insert into hse.form_versions(tenant_id,template_id,version,snapshot,published_by) values ('e1000000-0000-0000-0000-00000000000a',current_setting('t58.a')::uuid,1,'{}','e0000000-0000-0000-0000-000000000002')$$, '42501', 'form_approver_must_differ_from_author', 'L15 direct version insert by the author is refused too');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_approve_publish(current_setting('t58.a')::uuid,3)), 1, 'L16 a different approver publishes: version 1');
select extensions.is(((select status from hse.form_templates where id=current_setting('t58.a')::uuid)), 'published', 'L17 template is published');
select extensions.is(((select (snapshot_hash=encode(sha256(convert_to(snapshot::text,'UTF8')),'hex'))::text||'-'||approved_by::text||'-'||submitted_by::text||'-'||(snapshot->'definition'=extensions.d58())::text||'-'||(approved_at is not null)::text from hse.form_versions where template_id=current_setting('t58.a')::uuid and version=1)), 'true-e0000000-0000-0000-0000-000000000003-e0000000-0000-0000-0000-000000000002-true-true', 'L18 version row: hash matches the snapshot, approver, submitter, definition, time');
select extensions.is(((select count(*)::int from audit.events where action_key='hse.form_versions.insert' and record_type='hse.form_versions' and actor_user_id='e0000000-0000-0000-0000-000000000003')), 1, 'L19 audit event written for the approval (TB-05)');
select extensions.throws_ok($$update hse.form_versions set change_note='x' where template_id=current_setting('t58.a')::uuid$$, '42501', null, 'L20 published version cannot be updated (TB-03)');
select extensions.throws_ok($$delete from hse.form_versions where template_id=current_setting('t58.a')::uuid$$, '42501', null, 'L21 published version cannot be deleted (TB-03)');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$insert into hse.form_versions(tenant_id,template_id,version,snapshot,published_by) values ('e1000000-0000-0000-0000-00000000000a',current_setting('t58.a')::uuid,2,'{}','e0000000-0000-0000-0000-000000000003')$$, '22023', 'form_not_in_approval', 'L22 version insert on a template that is not in approval is refused');
reset role;
create function extensions.d58c() returns jsonb language sql as $f$
  select jsonb_set(jsonb_set(d, '{questions}', (select jsonb_agg(case when q->>'id'='q5' then jsonb_build_object('id','q6','sectionId','s1','type','short_text','title','{"en":"New","ar":"جديد"}'::jsonb,'config','{"maxLength":10}'::jsonb,'conditions','[]'::jsonb)
      when q->>'id'='q1' then jsonb_set(q,'{title,en}','"Full name"') else q end) from jsonb_array_elements(d->'questions') q)), '{sections,0,questionIds}', '["q1","q2","q3","q4","q6"]'::jsonb)
  from (select replace(extensions.d58t(),'"en":"Count"','"en":"Count 2"')::jsonb d) z $f$;
grant execute on function extensions.d58c() to anon, authenticated, service_role;
reset role;
create function extensions.d58b() returns jsonb language sql as $f$ select replace(extensions.d58t(),'"en":"Count"','"en":"Count 2"')::jsonb $f$;
grant execute on function extensions.d58b() to anon, authenticated, service_role;
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_save_draft(current_setting('t58.a')::uuid,3,'{"en":"Fire","ar":"حريق"}','Safety',extensions.d58b())), 4, 'L23 editing a published template reopens it as a draft with a new revision');
select extensions.is(((select status from hse.form_templates where id=current_setting('t58.a')::uuid)), 'draft', 'L24 the reopened template is a draft');
select api.form_submit_for_approval(current_setting('t58.a')::uuid,4,'v2: count title');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.lives_ok($$select api.form_approve_publish(current_setting('t58.a')::uuid,4)$$, 'L25 a different approver publishes the second version');
select extensions.is(((select max(version) from hse.form_versions where template_id=current_setting('t58.a')::uuid)), 2, 'L25b the server numbered the new version 2');
select extensions.is(((select count(*)::int from hse.form_versions where template_id=current_setting('t58.a')::uuid)), 2, 'L26 two versions exist and version 1 is unchanged');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select api.form_save_draft(current_setting('t58.a')::uuid,4,'{"en":"Fire","ar":"حريق"}','Safety',extensions.d58c());
select api.form_submit_for_approval(current_setting('t58.a')::uuid,5,'v3: new item');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000005',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_approve_publish(current_setting('t58.a')::uuid,5)), 3, 'L31 version 3 published by a third person');
select extensions.is(((api.form_compare_versions(current_setting('t58.a')::uuid,2,3)->'added')::text||(api.form_compare_versions(current_setting('t58.a')::uuid,2,3)->'removed')::text), '["q6"]["q5"]', 'L32 compare v2 to v3 lists the added and removed questions exactly (TB-06)');
select extensions.is(((api.form_compare_versions(current_setting('t58.a')::uuid,2,3)->'changed')::text), '[{"id": "q1", "fields": ["title"]}]', 'L33 compare v2 to v3 lists the changed question and field');
select extensions.is(((api.form_compare_versions(current_setting('t58.a')::uuid,1,2)->'changed')::text||(api.form_compare_versions(current_setting('t58.a')::uuid,1,2)->>'sections_changed')), '[{"id": "q2", "fields": ["title"]}]false', 'L34 compare v1 to v2 shows only the renamed question, sections unchanged');
select extensions.is(((api.form_compare_versions(current_setting('t58.a')::uuid,3,3)->>'identical')), 'true', 'L35 a version compared with itself is identical');
select extensions.throws_ok($$select api.form_compare_versions(current_setting('t58.a')::uuid,1,9)$$, '22023', 'form_version_not_found', 'L36 unknown version is refused');
select extensions.is(((select count(*)::int from hse.form_versions where template_id=current_setting('t58.a')::uuid and version in (1,2,3))), 3, 'L37 versions 1 to 3 all exist and numbering is continuous');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select api.form_save_draft(current_setting('t58.a')::uuid,5,'{"en":"Fire","ar":"حريق"}','Safety',extensions.d58c());
select api.form_submit_for_approval(current_setting('t58.a')::uuid,5,'v4 try');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_return_to_draft(current_setting('t58.a')::uuid,' ')$$, '23514', 'form_return_reason_required', 'L38 return needs a reason');
select extensions.lives_ok($$select api.form_return_to_draft(current_setting('t58.a')::uuid,'fix the wording')$$, 'L39 reviewer returns the template to the author');
select extensions.is(((select status||'-'||return_reason||'-'||coalesce(submitted_by::text,'none') from hse.form_templates where id=current_setting('t58.a')::uuid)), 'draft-fix the wording-none', 'L40 back to draft with the reason, submission cleared');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$update hse.form_templates set status='retired' where id=current_setting('t58.a')::uuid$$, '23514', 'form_status_transition_not_allowed', 'L41 draft cannot be retired directly');
select extensions.is(((select revision from hse.form_templates where id=current_setting('t58.a')::uuid)), 5, 'L42 revision before the spoof test');
update hse.form_templates set revision=99, submitted_by='e0000000-0000-0000-0000-000000000003', last_edited_by='e0000000-0000-0000-0000-000000000003' where id=current_setting('t58.a')::uuid;
select extensions.is(((select revision::text||'-'||coalesce(submitted_by::text,'none')||'-'||last_edited_by::text from hse.form_templates where id=current_setting('t58.a')::uuid)), '5-none-e0000000-0000-0000-0000-000000000002', 'L43 revision, submitter and last editor cannot be set by the client');
select extensions.throws_ok($$insert into hse.form_templates(tenant_id,title,category,status,definition,owner_membership_id,created_by) values ('e1000000-0000-0000-0000-00000000000a','{}','c','published','{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002')$$, '23514', 'form_insert_must_be_draft', 'L44 a client cannot insert a template as published');
select extensions.throws_ok($$update hse.form_templates set languages=array['fr'] where id=current_setting('t58.a')::uuid$$, '23514', null, 'L45 unsupported language is refused by the table check');
select api.form_submit_for_approval(current_setting('t58.a')::uuid,5,'v4');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select api.form_approve_publish(current_setting('t58.a')::uuid,5);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$update hse.form_templates set definition='{}' where id=current_setting('t58.a')::uuid$$, '23514', 'form_content_change_requires_draft', 'L46 content change on a published template needs it to go back to draft');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,'retired')$$, 'L47 published template is retired');
select extensions.is(((select status from hse.form_templates where id=current_setting('t58.a')::uuid)||'-'||(select count(*)::text from hse.form_versions where template_id=current_setting('t58.a')::uuid)), 'retired-4', 'L48 retired template keeps all 4 versions (old records stay readable)');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,'draft')$$, 'L49 retired template is restored as a draft');
select extensions.throws_ok($$select api.form_set_status(current_setting('t58.a')::uuid,'published')$$, '23514', 'form_status_transition_not_allowed', 'L50 status published cannot be set through the status function');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,'archived')$$, 'L51 draft is archived');
select extensions.throws_ok($$update hse.form_templates set status='published' where id=current_setting('t58.a')::uuid$$, '23514', 'form_status_transition_not_allowed', 'L52 archived cannot go to published');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,'draft')$$, 'L53 archived is restored as a draft');
select set_config('t58.c', api.form_clone(current_setting('t58.a')::uuid, null)::text, true);
select extensions.is(((select (id<>current_setting('t58.a')::uuid)::text||'-'||status||'-'||revision||'-'||(select count(*) from hse.form_versions v where v.template_id=t.id) from hse.form_templates t where id=current_setting('t58.c')::uuid)), 'true-draft-1-0', 'L54 clone: new id, draft, revision 1, no versions (TB-07)');
update hse.form_templates set definition='{"sections":[],"questions":[]}' where id=current_setting('t58.c')::uuid;
select extensions.is(((select (definition=extensions.d58c())::text from hse.form_templates where id=current_setting('t58.a')::uuid)), 'true', 'L55 editing the clone does not change the original (TB-07)');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000006',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_clone(current_setting('t58.a')::uuid)$$, '22023', 'form_not_found', 'L56 other company cannot clone');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_submit_for_approval(current_setting('t58.a')::uuid,7,'x')$$, '22023', 'form_not_found', 'L57 employee cannot see or submit a template');
reset role;
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select set_config('t58.d', api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"Sep","ar":"فصل"}','Safety',extensions.d58())::text, true);
select extensions.throws_ok($$update hse.form_templates set status='published' where id=current_setting('t58.d')::uuid$$, '23514', 'form_status_transition_not_allowed', 'L59 a draft cannot be moved straight to published');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select api.form_save_draft(current_setting('t58.d')::uuid,1,'{"en":"Sep","ar":"فصل"}','Safety',extensions.d58b());
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000005',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select api.form_submit_for_approval(current_setting('t58.d')::uuid,2,'second person edited, third person submits');
select extensions.is(((select last_edited_by::text||'-'||submitted_by::text from hse.form_templates where id=current_setting('t58.d')::uuid)), 'e0000000-0000-0000-0000-000000000003-e0000000-0000-0000-0000-000000000005', 'L60 last editor and submitter are two different people');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t58.d')::uuid,2)$$, '42501', 'form_approver_must_differ_from_author', 'L61 the last editor cannot approve');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000005',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t58.d')::uuid,2)$$, '42501', 'form_approver_must_differ_from_author', 'L62 the submitter cannot approve');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_approve_publish(current_setting('t58.d')::uuid,2)), 1, 'L63 the original creator, who did neither, can approve');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true);
select extensions.lives_ok($$insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values ('e5000000-0000-0000-0000-00000000000b','e1000000-0000-0000-0000-00000000000a','{"en":"Seed"}','t','published',1,'{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002')$$, 'L65 a seed insert by the database owner is not guarded even when a user id is left in the session');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values ('e5000000-0000-0000-0000-000000000009','e1000000-0000-0000-0000-00000000000a','{"en":"Adm"}','t','in_approval',1,'{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002');
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values ('e5000000-0000-0000-0000-00000000000a','e1000000-0000-0000-0000-00000000000a','{"en":"Ret"}','t','retired',1,'{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002');
select extensions.is(((select count(*)::int from hse.form_templates where status in ('in_approval','retired') and id::text like 'e5000000%')), 2, 'L58 DB admin can create rows in the new statuses (no user, unguarded)');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_approve_publish('e5000000-0000-0000-0000-000000000009',1)$$, '22023', 'form_validation_failed', 'L64 approval revalidates, so an invalid in-approval row cannot be published');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values ('e5000000-0000-0000-0000-00000000000c','e1000000-0000-0000-0000-00000000000a','{"en":"Ap"}','t','in_approval',1,'{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002');
insert into hse.form_versions(tenant_id,template_id,version,snapshot,published_by,approved_by,approved_at) values ('e1000000-0000-0000-0000-00000000000a','e5000000-0000-0000-0000-00000000000c',1,'{}','e0000000-0000-0000-0000-000000000005','e0000000-0000-0000-0000-000000000005',now());
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$update hse.form_templates set status='published' where id='e5000000-0000-0000-0000-00000000000c'$$, '42501', 'form_publish_requires_approval', 'L66 a version approved by someone else cannot be used to publish (approved_by is checked)');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
insert into hse.form_versions(tenant_id,template_id,version,snapshot,published_by,approved_by,approved_at) values ('e1000000-0000-0000-0000-00000000000a','e5000000-0000-0000-0000-00000000000c',2,'{}','e0000000-0000-0000-0000-000000000003','e0000000-0000-0000-0000-000000000003',now());
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.lives_ok($$update hse.form_templates set status='published' where id='e5000000-0000-0000-0000-00000000000c'$$, 'L67 positive control: a version approved by the caller in the same step allows publish');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
-- BEGIN EMBEDDED 058 ROLLBACK
-- Rollback of 058: drop the API, guards and helpers, map the new statuses back (in_approval -> draft, retired -> archived),
-- restore the old status check, drop the added columns (their data is lost). Existing published versions and templates stay.
drop function if exists api.form_compare_versions(uuid, integer, integer);
drop function if exists api.form_clone(uuid, jsonb);
drop function if exists api.form_set_status(uuid, text);
drop function if exists api.form_approve_publish(uuid, integer);
drop function if exists api.form_return_to_draft(uuid, text);
drop function if exists api.form_submit_for_approval(uuid, integer, text);
drop function if exists api.form_save_draft(uuid, integer, jsonb, text, jsonb, text[]);
drop function if exists api.form_create_draft(uuid, jsonb, text, jsonb, text[]);
drop function if exists api.form_validate(jsonb, text[], jsonb);
drop trigger if exists form_version_published on hse.form_versions;
drop trigger if exists form_version_insert_guard on hse.form_versions;
drop trigger if exists form_template_write_guard on hse.form_templates;
drop function if exists private.form_version_published();
drop function if exists private.guard_form_version_insert();
drop function if exists private.guard_form_template_write();
drop function if exists private.form_hash(jsonb);
drop function if exists private.form_session_user();
drop function if exists private.form_snapshot(uuid);
drop function if exists private.validate_form_definition(jsonb, text[], jsonb);
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
-- END EMBEDDED 058 ROLLBACK
select extensions.is(((select status from hse.form_templates where id='e5000000-0000-0000-0000-000000000009')||'-'||(select status from hse.form_templates where id='e5000000-0000-0000-0000-00000000000a')), 'draft-archived', 'R01 rollback maps in_approval to draft and retired to archived');
select extensions.is((coalesce(to_regprocedure('api.form_save_draft(uuid,integer,jsonb,text,jsonb,text[])')::text,'none')||'-'||coalesce(to_regprocedure('private.validate_form_definition(jsonb,text[],jsonb)')::text,'none')||'-'||(select count(*) from pg_trigger where tgname in ('form_template_write_guard','form_version_insert_guard','form_version_published'))), 'none-none-0', 'R02 rollback removes the API, validator and guards');
select extensions.is(((select count(*)::int from information_schema.columns where table_schema='hse' and table_name in ('form_templates','form_versions') and column_name in ('languages','change_note','return_reason','review_due_date','is_library','last_edited_by','submitted_by','submitted_at','snapshot_hash','approved_by','approved_at'))), 0, 'R03 rollback drops the added columns');
select extensions.is(((select pg_get_constraintdef(oid) from pg_constraint where conname='form_templates_status_check')), 'CHECK ((status = ANY (ARRAY[''draft''::text, ''published''::text, ''archived''::text])))', 'R04 rollback restores the old status check');
select extensions.is(((select count(*)::int from hse.form_versions where template_id=current_setting('t58.a')::uuid)), 4, 'R05 rollback keeps the published versions');
select * from extensions.finish();
rollback;