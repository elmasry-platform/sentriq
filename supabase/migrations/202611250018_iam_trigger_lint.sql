begin;
create or replace function private.guard_role_version_content() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_version uuid; v_status text;
begin
 if tg_table_name='role_versions' then
  if tg_op='DELETE' or (to_jsonb(old)->>'status')='published' then
   raise exception 'published_role_version_is_immutable' using errcode='42501'; end if;
 else
  v_version:=case when tg_op='DELETE' then (to_jsonb(old)->>'role_version_id')::uuid else (to_jsonb(new)->>'role_version_id')::uuid end;
  select status into v_status from iam.role_versions where id=v_version;
  if v_status='published' then raise exception 'published_role_content_is_immutable' using errcode='42501'; end if;
 end if;
 if tg_op='DELETE' then return old; end if;
 return new;
end $$;
create or replace function private.guard_permission_profile_immutability() returns trigger
language plpgsql set search_path='' as $$
begin
 if tg_table_name='permission_profile_versions' and tg_op='UPDATE'
  and not coalesce((to_jsonb(old)->>'sealed')::boolean,false) and coalesce((to_jsonb(new)->>'sealed')::boolean,false)
  and to_jsonb(new)-'sealed'=to_jsonb(old)-'sealed' then return new;end if;
 if tg_op='DELETE' or to_jsonb(new)-array['id'] is distinct from to_jsonb(old)-array['id'] then
  raise exception 'permission_profile_version_content_is_immutable' using errcode='42501';end if;
 return new;
end $$;
create or replace function private.validate_assignment_source_scope() returns trigger
language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype;d iam.delegation_envelopes%rowtype;v_scope uuid;
begin
 select * into a from iam.membership_roles where tenant_id=new.tenant_id and id=new.membership_role_id;
 if a.source_delegation_id is null then return new;end if;
 select * into d from iam.delegation_envelopes where tenant_id=new.tenant_id and id=a.source_delegation_id;
 if not private.decision_source_valid(d.id,d.tenant_id) then raise exception 'role_source_expired' using errcode='42501';end if;
 if d.level in ('tenant','employees_default') then return new;end if;
 if tg_table_name='membership_role_sites' and (d.level<>'site' or d.site_id<>(to_jsonb(new)->>'site_id')::uuid) then
  raise exception 'role_site_outside_exact_source' using errcode='42501';end if;
 if tg_table_name='membership_role_org_units' and (d.level<>'org_unit' or d.org_unit_id<>(to_jsonb(new)->>'org_unit_id')::uuid) then
  raise exception 'role_org_outside_exact_source' using errcode='42501';end if;
 return new;
end $$;
create or replace function private.guard_role_binding_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype;p record;v_site uuid;v_org uuid;v_action text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 select * into a from iam.membership_roles where tenant_id=new.tenant_id and id=new.membership_role_id;
 if tg_table_name='membership_role_sites' then
  v_site:=(to_jsonb(new)->>'site_id')::uuid;select org_unit_id into v_org from core.sites where tenant_id=new.tenant_id and id=v_site;
 else v_org:=(to_jsonb(new)->>'org_unit_id')::uuid;end if;
 for p in select * from iam.role_version_permissions where role_version_id=a.role_version_id
  and scope_kind=case when tg_table_name='membership_role_sites' then 'site' else 'org_unit' end loop
  if p.can_read or p.can_write then perform private.assert_permission_grantable(new.tenant_id,p.permission_key,p.can_write,v_site,v_org);end if;
  foreach v_action in array p.actions loop
   if v_action not in ('read','write') then perform private.assert_action_delegable(new.tenant_id,p.permission_key,v_action,v_site,v_org);end if;
  end loop;
 end loop;
 return new;
end $$;
create or replace function private.capture_assignment_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;v_explicit iam.delegation_envelopes%rowtype;
begin
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id then raise exception 'assignment_source_is_immutable' using errcode='23514';end if;
  return new;
 end if;
 if new.source_delegation_id is not null then
  select * into v_explicit from iam.delegation_envelopes where tenant_id=new.tenant_id and id=new.source_delegation_id;
  if not private.decision_source_valid(v_explicit.id,v_explicit.tenant_id) or not 'role_assignment'=any(v_explicit.allowed_capabilities)
   or not exists(select 1 from iam.memberships t where t.tenant_id=new.tenant_id and t.id=new.membership_id
    and (v_explicit.level<>'employees_default' or t.member_role='employee')) then
   raise exception 'explicit_assignment_source_invalid' using errcode='42501';end if;
  return new;
 end if;
 if session_user='postgres' and current_setting('role')='none' then return new;end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=private.request_actor_id() and status='active';
 if not found then raise exception 'assignment_actor_required' using errcode='42501';end if;
 if m.member_role<>'company_superadmin' then
  select id into new.source_delegation_id from iam.delegation_envelopes d where tenant_id=new.tenant_id and delegate_membership_id=m.id
   and private.decision_source_valid(d.id,d.tenant_id) and 'role_assignment'=any(allowed_capabilities)
   and (level='tenant' or (level='employees_default' and exists(select 1 from iam.memberships t where t.tenant_id=new.tenant_id and t.id=new.membership_id and t.member_role='employee')))
   order by created_at desc,id limit 1;
  if new.source_delegation_id is null then raise exception 'assignment_source_envelope_required' using errcode='42501';end if;
 end if;
 return new;
end $$;
commit;
