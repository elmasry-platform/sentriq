-- 058 (HSE M01): form template lifecycle, publish validation, hashed immutable versions, compare.
-- The test embeds the rollback (to rebuild the old state, because CI applies every migration first) and the migration
-- (checked against the files by scripts/check_058_embed.sh). Rolled back at the end.
begin;
select extensions.plan(167);
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
insert into auth.users(id,aud,role,email,email_confirmed_at,created_at,updated_at) select ('e0000000-0000-0000-0000-'||lpad(i::text,12,'0'))::uuid,'authenticated','authenticated','m-'||i||'@example.test',now(),now(),now() from generate_series(1,8) i;
select private.bootstrap_platform_owner('e0000000-0000-0000-0000-000000000001');
insert into core.tenants(id,name,created_by) values ('e1000000-0000-0000-0000-00000000000a','M58','e0000000-0000-0000-0000-000000000001'),('e1000000-0000-0000-0000-00000000000b','M58 other','e0000000-0000-0000-0000-000000000001');
insert into iam.memberships(id,tenant_id,user_id,member_role,email,status) values
('e2000000-0000-0000-0000-000000000002','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000002','company_superadmin','m-2@example.test','active'),
('e2000000-0000-0000-0000-000000000003','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000003','company_superadmin','m-3@example.test','active'),
('e2000000-0000-0000-0000-000000000004','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000004','employee','m-4@example.test','active'),
('e2000000-0000-0000-0000-000000000005','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000005','company_superadmin','m-5@example.test','active'),
('e2000000-0000-0000-0000-000000000008','e1000000-0000-0000-0000-00000000000a','e0000000-0000-0000-0000-000000000008','company_superadmin','m-8@example.test','active'),
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

drop function if exists api.form_set_status(uuid, integer, text);
create or replace function api.form_set_status(p_id uuid, p_expected_revision integer, p_status text, p_reason text default null) returns void
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
  perform set_config('sentriq.form_reason', coalesce(nullif(btrim(p_reason), ''), ''), true);
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

-- Audit of status changes: who, what, from and to, when, why, and the approver. Written for every status change,
-- including direct table updates. audit.events is append-only (immutable trigger, authenticated has select only).
create or replace function private.audit_form_status() returns trigger language plpgsql security definer set search_path = '' as $f$
declare v_reason text; v_approver uuid; v_version int;
begin
  if new.status is not distinct from old.status then return null; end if;
  v_reason := coalesce(
    case when old.status = 'in_approval' and new.status = 'draft' then new.return_reason end,
    case when old.status = 'draft' and new.status = 'in_approval' then new.change_note end,
    nullif(current_setting('sentriq.form_reason', true), ''));
  if old.status = 'in_approval' and new.status = 'published' then
    select v.approved_by, v.version into v_approver, v_version from hse.form_versions v where v.template_id = new.id order by v.version desc limit 1;
  end if;
  insert into audit.events(tenant_id, actor_user_id, actor_membership_id, scope_kind, action_key, record_type, record_id, summary)
  values (new.tenant_id, auth.uid(), private.current_membership_id(new.tenant_id), 'tenant',
    'hse.form_templates.status.' || new.status, 'hse.form_templates', new.id,
    jsonb_build_object('from', old.status, 'to', new.status, 'revision', new.revision, 'reason', v_reason,
      'approver', v_approver, 'version', v_version, 'submitted_by', new.submitted_by));
  return null;
end $f$;
revoke all on function private.audit_form_status() from public, anon, authenticated;
drop trigger if exists z_form_status_audit on hse.form_templates;
create trigger z_form_status_audit after update on hse.form_templates
  for each row when (old.status is distinct from new.status) execute function private.audit_form_status();

do $g$
declare r record;
begin
  for r in select p.oid::regprocedure as sig from pg_proc p where p.pronamespace = 'api'::regnamespace
     and p.proname in ('form_validate','form_create_draft','form_save_draft','form_submit_for_approval','form_return_to_draft','form_approve_publish','form_set_status','form_clone','form_compare_versions','form_version_get') loop
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
select extensions.throws_ok($$select api.form_return_to_draft(current_setting('t58.a')::uuid,5,' ')$$, '23514', 'form_return_reason_required', 'L38 return needs a reason');
select extensions.lives_ok($$select api.form_return_to_draft(current_setting('t58.a')::uuid,5,'fix the wording')$$, 'L39 reviewer returns the template to the author');
select extensions.is(((select status||'-'||return_reason||'-'||coalesce(submitted_by::text,'none') from hse.form_templates where id=current_setting('t58.a')::uuid)), 'draft-fix the wording-none', 'L40 back to draft with the reason, submission cleared');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select "returnReason" from api.v_forms where id=current_setting('t58.a')::uuid)), 'fix the wording', 'W14 api.v_forms shows the return reason after a return');
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
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,5,'retired')$$, 'L47 published template is retired');
select extensions.is(((select status from hse.form_templates where id=current_setting('t58.a')::uuid)||'-'||(select count(*)::text from hse.form_versions where template_id=current_setting('t58.a')::uuid)), 'retired-4', 'L48 retired template keeps all 4 versions (old records stay readable)');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,5,'draft')$$, 'L49 retired template is restored as a draft');
select extensions.throws_ok($$select api.form_set_status(current_setting('t58.a')::uuid,5,'published')$$, '23514', 'form_status_transition_not_allowed', 'L50 status published cannot be set through the status function');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,5,'archived')$$, 'L51 draft is archived');
select extensions.throws_ok($$update hse.form_templates set status='published' where id=current_setting('t58.a')::uuid$$, '23514', 'form_status_transition_not_allowed', 'L52 archived cannot go to published');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.a')::uuid,5,'draft')$$, 'L53 archived is restored as a draft');
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
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t58.d')::uuid,2)$$, '42501', 'form_approver_must_differ_from_author', 'L63 the original creator, who neither edited last nor submitted, cannot approve');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000008',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is((api.form_approve_publish(current_setting('t58.d')::uuid,2)), 1, 'L63a positive control: a fourth person who did none of it approves');
reset role;
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select languages::text||'-'||"changeNote"||'-'||"lastEditedBy"::text||'-'||"submittedBy"::text||'-'||status||'-'||"isLibrary"::text from api.v_forms where id=current_setting('t58.d')::uuid)), '{en,ar}-second person edited, third person submits-e0000000-0000-0000-0000-000000000003-e0000000-0000-0000-0000-000000000005-published-false', 'W01 api.v_forms exposes languages, change note, last editor, submitter, library flag');
select extensions.is(((select ("returnReason" is null)::text||'-'||("submittedAt" is not null)::text||'-'||("reviewDueDate" is null)::text from api.v_forms where id=current_setting('t58.d')::uuid)), 'true-true-true', 'W02 api.v_forms exposes return reason, submitted time and review due date');
select extensions.is(((select count(*)::int from information_schema.columns where table_schema='api' and table_name='v_forms')), 17, 'W03 api.v_forms keeps the 9 old columns and adds 8');
select extensions.is(((select version::text||'-'||length("snapshotHash")::text||'-'||"approvedBy"::text||'-'||"submittedBy"::text||'-'||("approvedAt" is not null)::text from api.v_form_versions where "templateId"=current_setting('t58.d')::uuid)), '1-64-e0000000-0000-0000-0000-000000000008-e0000000-0000-0000-0000-000000000005-true', 'W04 api.v_form_versions lists version, hash, approver, submitter and approval time');
select extensions.is(((select count(*)::int from information_schema.columns where table_schema='api' and table_name='v_form_versions' and column_name='snapshot')), 0, 'W05 the version list has no snapshot body column');
select extensions.is(((api.form_version_get(current_setting('t58.d')::uuid,1)->'definition' = extensions.d58b())::text||'-'||(api.form_version_get(current_setting('t58.d')::uuid,1)->>'change_note')), 'true-second person edited, third person submits', 'W06 api.form_version_get returns the stored snapshot');
select extensions.throws_ok($$select api.form_version_get(current_setting('t58.d')::uuid,9)$$, '22023', 'form_version_not_found', 'W07 unknown version is refused');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000006',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select count(*)::int from api.v_form_versions where "templateId"=current_setting('t58.d')::uuid)), 0, 'W08 a superadmin of another company sees no versions');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000006',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$select api.form_version_get(current_setting('t58.d')::uuid,1)$$, '22023', 'form_version_not_found', 'W09 the other company cannot get the snapshot either');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000006',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select count(*)::int from api.v_forms where id=current_setting('t58.d')::uuid)), 0, 'W10 the other company does not see the template in api.v_forms');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select count(*)::int from api.v_form_versions)), 0, 'W11 an employee without forms.read sees no versions');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select prosecdef::text from pg_proc where proname='validate_form_definition' and pronamespace='private'::regnamespace)), 'false', 'W12 the validator is not security definer (no definer function granted to authenticated)');
select extensions.is(((select jsonb_array_length(api.form_validate('e1000000-0000-0000-0000-00000000000a','{"en":"T"}','{en,ar}','{}')))), 3, 'W13 an authenticated user can call api.form_validate');
reset role; set local statement_timeout='5s';
select extensions.lives_ok($$select extensions.v58(replace(replace(extensions.d58t(),'"type":"integer"','"type":"decimal"'),'"min":0,"max":10','"min":0,"max":10,"precision":99999999999')::jsonb)$$, 'V31a a hostile number does not raise an error');
select extensions.is((extensions.v58(replace(replace(extensions.d58t(),'"type":"integer"','"type":"decimal"'),'"min":0,"max":10','"min":0,"max":10,"precision":99999999999')::jsonb)), 'decimal_precision_invalid', 'V31 decimal precision 99999999999 is a coded error, not a cast failure');
select extensions.lives_ok($$select extensions.v58(extensions.rep58('"maxLength":100','"maxLength":99999999999999999999'))$$, 'V32a a 20-digit number does not raise an error');
select extensions.is((extensions.v58(extensions.rep58('"maxLength":100','"maxLength":99999999999999999999'))), 'text_length_invalid', 'V32 a 20-digit max length is a coded error');
select extensions.is((extensions.v58(extensions.rep58('"id":"q5","sectionId":"s1","type":"instruction","title":{"en":"Note","ar":"ملاحظة"},"config":{}','"id":"q5","sectionId":"s1","type":"photo","title":{"en":"Note","ar":"ملاحظة"},"config":{"maxFiles":99999999999,"maxBytes":99999999999999999999}'))), 'file_size_limit_invalid', 'V33 a huge file size limit is a coded error');
select extensions.is((extensions.v58(jsonb_build_object('sections','[]'::jsonb,'questions',(select jsonb_agg(jsonb_build_object('id','i'||k,'sectionId','s1','type','instruction','title','{}'::jsonb,'config','{}'::jsonb)) from generate_series(1,301) k)))), 'too_many_questions', 'V34 301 questions return one coded error at once');
select extensions.is((extensions.v58(jsonb_build_object('sections','[]'::jsonb,'questions',jsonb_build_array(jsonb_build_object('id','q1','title',repeat('x',2500000)))))), 'definition_too_large', 'V35 a definition over 1 MB returns one coded error at once');
select extensions.is((extensions.v58(extensions.rep58('"type":"instruction"','"type":"reference"'))), 'question_type_not_supported', 'V36 reference is refused at validation until the runner supports it');
select extensions.is((extensions.v58(extensions.rep58('"type":"instruction"','"type":"user"'))), 'question_type_not_supported', 'V36 user is refused at validation until the runner supports it');
select extensions.is((extensions.v58(extensions.rep58('"type":"instruction"','"type":"site"'))), 'question_type_not_supported', 'V36 site is refused at validation until the runner supports it');
select extensions.is((extensions.v58(extensions.rep58('"type":"instruction"','"type":"location"'))), 'question_type_not_supported', 'V36 location is refused at validation until the runner supports it');
select extensions.is((extensions.v58(extensions.rep58('"type":"instruction"','"type":"barcode_qr"'))), 'question_type_not_supported', 'V36 barcode_qr is refused at validation until the runner supports it');
select extensions.is((extensions.v58(extensions.rep58('"type":"instruction"','"type":"repeat_group"'))), 'question_type_not_supported,repeat_rows_invalid', 'V36 repeat_group is refused at validation until the runner supports it');
reset role; set local statement_timeout=0;
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select set_config('t58.r', api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"Rev","ar":"مراجعة"}','Safety',extensions.d58())::text, true);
select extensions.throws_ok($$select api.form_set_status(current_setting('t58.r')::uuid,7,'archived')$$, '40001', 'form_revision_conflict', 'E01 set_status with a stale revision is refused');
select extensions.lives_ok($$select api.form_set_status(current_setting('t58.r')::uuid,1,'archived','no longer needed')$$, 'E02 set_status with the right revision works');
select extensions.throws_ok($$select api.form_return_to_draft(current_setting('t58.r')::uuid,7,'x reason')$$, '40001', 'form_revision_conflict', 'E03 return_to_draft with a stale revision is refused');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select count(*)::int from api.v_forms)), 0, 'E04 the employee without forms.read sees no templates');
select extensions.throws_ok($$select api.form_validate('e1000000-0000-0000-0000-00000000000a','{"en":"T"}','{en,ar}','{}')$$, '42501', 'form_not_permitted', 'E05 form_validate refuses an employee without forms.read');
select extensions.throws_ok($$select api.form_create_draft('e1000000-0000-0000-0000-00000000000a','{"en":"X","ar":"س"}','c','{}')$$, '42501', 'new row violates row-level security policy for table "form_templates"', 'E06 form_create_draft refuses the employee: the refusal comes from the insert policy on form_templates, the function has no check of its own');
select extensions.throws_ok($$select api.form_save_draft(current_setting('t58.d')::uuid,3,'{"en":"X","ar":"س"}','c','{}')$$, '22023', 'form_not_found', 'E07 form_save_draft: the employee cannot see the template (not found, no existence leak)');
select extensions.throws_ok($$select api.form_submit_for_approval(current_setting('t58.d')::uuid,3,'n')$$, '22023', 'form_not_found', 'E08 form_submit_for_approval: not found for the employee');
select extensions.throws_ok($$select api.form_return_to_draft(current_setting('t58.d')::uuid,3,'r')$$, '22023', 'form_not_found', 'E09 form_return_to_draft: not found for the employee');
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t58.d')::uuid,3)$$, '22023', 'form_not_found', 'E10 form_approve_publish: not found for the employee');
select extensions.throws_ok($$select api.form_set_status(current_setting('t58.d')::uuid,3,'archived')$$, '22023', 'form_not_found', 'E11 form_set_status: not found for the employee');
select extensions.throws_ok($$select api.form_clone(current_setting('t58.d')::uuid,null)$$, '22023', 'form_not_found', 'E12 form_clone: not found for the employee');
select extensions.throws_ok($$select api.form_compare_versions(current_setting('t58.d')::uuid,1,1)$$, '22023', 'form_version_not_found', 'E13 form_compare_versions: not found for the employee');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000002',true);
select extensions.lives_ok($$insert into hse.form_templates(id,tenant_id,title,category,status,revision,definition,owner_membership_id,created_by) values ('e5000000-0000-0000-0000-00000000000b','e1000000-0000-0000-0000-00000000000a','{"en":"Seed"}','t','published',1,'{}','e2000000-0000-0000-0000-000000000002','e0000000-0000-0000-0000-000000000002')$$, 'L65 a seed insert by the database owner is not guarded even when a user id is left in the session');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select set_config('sentriq.migration_runner','on',true); insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,granted_by,reason) values ('e1000000-0000-0000-0000-00000000000a','e2000000-0000-0000-0000-000000000004','hse.forms.read','allow','tenant',true,false,'e0000000-0000-0000-0000-000000000001','read only employee'); select set_config('sentriq.migration_runner','off',true);
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select count(*)::int from api.v_forms where id=current_setting('t58.d')::uuid)), 1, 'E14 the read-only employee sees the template');
select extensions.throws_ok($$select api.form_save_draft(current_setting('t58.d')::uuid,3,'{"en":"X","ar":"س"}','c','{}')$$, '42501', 'form_not_permitted', 'E15 form_save_draft refuses the read-only employee with 42501');
select extensions.throws_ok($$select api.form_submit_for_approval(current_setting('t58.d')::uuid,3,'n')$$, '42501', 'form_not_permitted', 'E16 form_submit_for_approval refuses the read-only employee');
select extensions.throws_ok($$select api.form_return_to_draft(current_setting('t58.d')::uuid,3,'r')$$, '42501', 'form_not_permitted', 'E17 form_return_to_draft refuses the read-only employee');
select extensions.throws_ok($$select api.form_approve_publish(current_setting('t58.d')::uuid,3)$$, '42501', 'form_not_permitted', 'E18 form_approve_publish refuses the read-only employee');
select extensions.throws_ok($$select api.form_set_status(current_setting('t58.d')::uuid,3,'archived')$$, '42501', 'form_not_permitted', 'E19 form_set_status refuses the read-only employee');
select extensions.throws_ok($$select api.form_clone(current_setting('t58.d')::uuid,null)$$, '42501', null, 'E20 form_clone refuses the read-only employee');
select extensions.throws_ok($$insert into hse.form_templates(tenant_id,title,category,status,definition,owner_membership_id,created_by) values ('e1000000-0000-0000-0000-00000000000a','{}','c','draft','{}','e2000000-0000-0000-0000-000000000004','e0000000-0000-0000-0000-000000000004')$$, '42501', null, 'E21 direct insert is refused for the read-only employee');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((select count(*)::int from api.v_form_versions where "templateId"=current_setting('t58.d')::uuid)), 1, 'E22 the read-only employee can list versions and compare');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000004',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.is(((api.form_compare_versions(current_setting('t58.d')::uuid,1,1)->>'identical')), 'true', 'E23 the read-only employee can compare versions');
reset role; select set_config('sentriq.migration_runner','on',true); delete from iam.member_permission_decisions where membership_id='e2000000-0000-0000-0000-000000000004' and permission_key='hse.forms.read'; select set_config('sentriq.migration_runner','off',true);
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
select extensions.is((array_to_string(private.form_runnable_types(), ',')), 'short_text,long_text,integer,decimal,date,time,datetime,boolean,single_select,multi_select,photo,file,attestation,signature,instruction,gps,calculated', 'T01 the runnable types are pinned (scripts/check_form_type_parity.py compares them with the runner)');
select extensions.is(((select array_to_string(array(select t from unnest(private.form_field_types()) t where t <> all (private.form_runnable_types())), ','))), 'reference,user,site,location,barcode_qr,repeat_group', 'T02 exactly these builder types are blocked at publish');
reset role; select set_config('request.jwt.claim.sub','',true); select set_config('request.jwt.claims','',true);
select extensions.is(((select s->>'from'||'>'||(s->>'to')||'|'||(s->>'reason') from (select summary s from audit.events where record_id=current_setting('t58.a')::uuid and action_key='hse.form_templates.status.draft' and summary->>'reason'='fix the wording') x)), 'in_approval>draft|fix the wording', 'AU01 a return is audited with old status, new status and the reason');
select extensions.is(((select count(*)::int from audit.events where record_id=current_setting('t58.a')::uuid and action_key='hse.form_templates.status.retired' and actor_user_id is not null and actor_membership_id is not null and created_at is not null)), 1, 'AU02 a retire is audited with actor, membership and time');
select extensions.is(((select summary->>'reason' from audit.events where record_id=current_setting('t58.d')::uuid and action_key='hse.form_templates.status.in_approval')), 'second person edited, third person submits', 'AU03 a submit is audited with the change note as reason');
select extensions.is(((select actor_user_id::text from audit.events where record_id=current_setting('t58.d')::uuid and action_key='hse.form_templates.status.in_approval')), 'e0000000-0000-0000-0000-000000000005', 'AU04 the submit audit names the submitter as actor');
select extensions.is(((select (summary->>'approver')||'-'||(summary->>'from')||'-'||(summary->>'version')||'-'||actor_user_id::text from audit.events where record_id=current_setting('t58.d')::uuid and action_key='hse.form_templates.status.published')), 'e0000000-0000-0000-0000-000000000008-in_approval-1-e0000000-0000-0000-0000-000000000008', 'AU05 a publish is audited with the approver, the old status, the version and the actor');
select extensions.is(((select summary->>'reason' from audit.events where record_id=current_setting('t58.r')::uuid and action_key='hse.form_templates.status.archived')), 'no longer needed', 'AU06 an archive keeps the reason given to form_set_status');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$update audit.events set summary='{}' where record_id=current_setting('t58.d')::uuid$$, '42501', null, 'AU07 an app role cannot update audit events');
reset role; select set_config('request.jwt.claim.sub','e0000000-0000-0000-0000-000000000003',true); select set_config('request.jwt.claims','',true); set local role authenticated;
select extensions.throws_ok($$delete from audit.events where record_id=current_setting('t58.d')::uuid$$, '42501', null, 'AU08 an app role cannot delete audit events');
reset role;
-- BEGIN EMBEDDED 058 ROLLBACK
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
-- END EMBEDDED 058 ROLLBACK
select extensions.is(((select status from hse.form_templates where id='e5000000-0000-0000-0000-000000000009')||'-'||(select status from hse.form_templates where id='e5000000-0000-0000-0000-00000000000a')), 'draft-archived', 'R01 rollback maps in_approval to draft and retired to archived');
select extensions.is((coalesce(to_regprocedure('api.form_save_draft(uuid,integer,jsonb,text,jsonb,text[])')::text,'none')||'-'||coalesce(to_regprocedure('private.validate_form_definition(jsonb,text[],jsonb)')::text,'none')||'-'||(select count(*) from pg_trigger where tgname in ('form_template_write_guard','form_version_insert_guard','form_version_published'))), 'none-none-0', 'R02 rollback removes the API, validator and guards');
select extensions.is(((select count(*)::int from information_schema.columns where table_schema='hse' and table_name in ('form_templates','form_versions') and column_name in ('languages','change_note','return_reason','review_due_date','is_library','last_edited_by','submitted_by','submitted_at','snapshot_hash','approved_by','approved_at'))), 0, 'R03 rollback drops the added columns');
select extensions.is(((select pg_get_constraintdef(oid) from pg_constraint where conname='form_templates_status_check')), 'CHECK ((status = ANY (ARRAY[''draft''::text, ''published''::text, ''archived''::text])))', 'R04 rollback restores the old status check');
select extensions.is(((select count(*)::int from hse.form_versions where template_id=current_setting('t58.a')::uuid)), 4, 'R05 rollback keeps the published versions');
select extensions.is(((select count(*)::int from information_schema.columns where table_schema='api' and table_name='v_forms')::text||'-'||coalesce(to_regclass('api.v_form_versions')::text,'none')||'-'||coalesce(to_regprocedure('api.form_version_get(uuid,integer)')::text,'none')), '9-none-none', 'R06 rollback restores the original api.v_forms and removes the version view and get');
select * from extensions.finish();
rollback;