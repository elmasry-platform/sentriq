-- Final grant-time checks cover each named action and actual assigned scope.
begin;
create or replace function private.assert_action_delegable(p_tenant uuid,p_permission text,p_action text,p_site uuid,p_org uuid)
returns void language plpgsql security definer set search_path='' as $$
declare v_membership uuid;
begin
 select id into v_membership from iam.memberships where tenant_id=p_tenant and user_id=private.request_actor_id() and status='active';
 if v_membership is null or not api.authorize(p_tenant,p_permission,p_action,p_site,p_org)
  or exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant and l.membership_id=v_membership
   and l.capability_key=p_permission and (not l.can_use or not l.can_delegate)) then
  raise exception 'named_action_outside_delegable_authority' using errcode='42501'; end if;
end $$;
create or replace function private.guard_action_composition_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare a text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 foreach a in array new.actions loop
  if a not in ('read','write') then
   perform private.assert_action_delegable(new.tenant_id,new.permission_key,a,
    (to_jsonb(new)->>'site_id')::uuid,(to_jsonb(new)->>'org_unit_id')::uuid);
  end if;
 end loop;
 return new;
end $$;
create or replace function private.guard_assigned_role_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare p record;a text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if new.role_version_id is not null then
  for p in select * from iam.role_version_permissions where role_version_id=new.role_version_id loop
   if p.scope_kind='tenant' then
    if p.can_read or p.can_write then
     perform private.assert_permission_grantable(new.tenant_id,p.permission_key,p.can_write,null,null);
    end if;
    foreach a in array p.actions loop
     if a not in ('read','write') then perform private.assert_action_delegable(new.tenant_id,p.permission_key,a,null,null); end if;
    end loop;
   end if;
  end loop;
 end if;
 return new;
end $$;
create or replace function private.guard_role_binding_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype;p record;v_site uuid;v_org uuid;v_action text;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 select * into a from iam.membership_roles where tenant_id=new.tenant_id and id=new.membership_role_id;
 if tg_table_name='membership_role_sites' then
  v_site:=new.site_id;select org_unit_id into v_org from core.sites where tenant_id=new.tenant_id and id=v_site;
 else v_org:=new.org_unit_id;end if;
 for p in select * from iam.role_version_permissions where role_version_id=a.role_version_id
  and scope_kind=case when tg_table_name='membership_role_sites' then 'site' else 'org_unit' end loop
  if p.can_read or p.can_write then perform private.assert_permission_grantable(new.tenant_id,p.permission_key,p.can_write,v_site,v_org);end if;
  foreach v_action in array p.actions loop
   if v_action not in ('read','write') then perform private.assert_action_delegable(new.tenant_id,p.permission_key,v_action,v_site,v_org);end if;
  end loop;
 end loop;
 return new;
end $$;
-- Invalidation affects named decisions as well as legacy read/write decisions.
create or replace function private.suspend_envelope_decisions() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status<>'active' then
  update iam.member_permission_decisions set status='suspended' where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.permission_action_grants set status='suspended' where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
 end if;
 return new;
end $$;
revoke all on function private.assert_action_delegable(uuid,text,text,uuid,uuid) from public,anon,authenticated,service_role;
commit;
