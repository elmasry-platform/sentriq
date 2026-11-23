-- Explicit action composition for reusable roles and baseline profiles.
begin;
alter table iam.role_version_permissions add column actions text[] not null default '{}';
alter table iam.permission_profile_permissions add column actions text[] not null default '{}';
-- Existing rows retain exactly read/write semantics, never approve/export.
alter table iam.role_version_permissions disable trigger role_version_permission_immutable;
update iam.role_version_permissions set actions=array_remove(array[case when can_read then 'read' end,case when can_write then 'write' end],null);
alter table iam.role_version_permissions enable trigger role_version_permission_immutable;
alter table iam.permission_profile_permissions disable trigger permission_profile_permission_immutable;
update iam.permission_profile_permissions set actions=array_remove(array[case when can_read then 'read' end,case when can_write then 'write' end],null);
alter table iam.permission_profile_permissions enable trigger permission_profile_permission_immutable;
alter table iam.role_version_permissions drop constraint role_version_permissions_check;
alter table iam.role_version_permissions add constraint role_permission_content_required check(can_read or can_write or cardinality(actions)>0);
alter table iam.permission_profile_permissions drop constraint permission_profile_permissions_check;
alter table iam.permission_profile_permissions add constraint profile_permission_content_required check(can_read or can_write or cardinality(actions)>0);

create or replace function private.validate_catalog_actions() returns trigger
language plpgsql security definer set search_path='' as $$
declare c iam.permission_catalog%rowtype;
begin
 if cardinality(new.actions)=0 then
  new.actions:=array_remove(array[case when new.can_read then 'read' end,case when new.can_write then 'write' end],null);
 elsif new.can_read is distinct from ('read'=any(new.actions)) or new.can_write is distinct from ('write'=any(new.actions)) then
  raise exception 'action_flags_must_match_catalog_actions' using errcode='23514';
 end if;
 select * into c from iam.permission_catalog where permission_key=new.permission_key and enabled;
 if not found or not new.scope_kind=any(c.supported_scope_kinds)
  or not new.actions<@c.supported_actions or exists(select 1 from unnest(new.actions) x where x is null)
  or cardinality(new.actions)<>(select count(distinct x) from unnest(new.actions) x) then
  raise exception 'unsupported_catalog_action_or_scope' using errcode='23514'; end if;
 return new;
end $$;
create trigger catalog_role_actions before insert or update on iam.role_version_permissions
 for each row execute function private.validate_catalog_actions();
create trigger catalog_profile_actions before insert or update on iam.permission_profile_permissions
 for each row execute function private.validate_catalog_actions();

create or replace function private.functional_action_allowed(p_tenant uuid,p_membership uuid,p_permission text,p_action text,
 p_site uuid,p_org uuid,p_task_kind text,p_task uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(
  select 1 from iam.membership_roles mr
   join iam.memberships m on m.tenant_id=mr.tenant_id and m.id=mr.membership_id and m.status='active'
   join iam.roles r on r.id=mr.role_id and r.tenant_id=mr.tenant_id and r.active
   join iam.role_versions v on v.tenant_id=mr.tenant_id and v.id=mr.role_version_id and v.role_id=r.id and v.status='published'
   join iam.role_version_permissions p on p.tenant_id=mr.tenant_id and p.role_version_id=v.id and p.permission_key=p_permission
  where mr.tenant_id=p_tenant and mr.membership_id=p_membership
   and m.member_role in ('company_admin','employee') and r.role_family=case when m.member_role='employee' then 'employee' else 'admin' end
   and v.role_family=r.role_family and p_action=any(p.actions) and mr.revoked_at is null
   and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
   and (p.scope_kind='tenant'
    or (p.scope_kind='site' and exists(select 1 from iam.membership_role_sites b where b.tenant_id=mr.tenant_id
      and b.membership_role_id=mr.id and b.site_id=p_site and b.revoked_at is null and b.granted_at<=now() and (b.ends_at is null or now()<b.ends_at)))
    or (p.scope_kind='org_unit' and exists(select 1 from iam.membership_role_org_units b where b.tenant_id=mr.tenant_id
      and b.membership_role_id=mr.id and b.org_unit_id=p_org and b.revoked_at is null and b.granted_at<=now() and (b.ends_at is null or now()<b.ends_at))))
 ) or exists(
  select 1 from iam.membership_permission_profiles mp
   join iam.memberships m on m.tenant_id=mp.tenant_id and m.id=mp.membership_id and m.status='active'
   join iam.permission_profiles pr on pr.tenant_id=mp.tenant_id and pr.id=mp.profile_id and pr.active
   join iam.permission_profile_versions v on v.tenant_id=mp.tenant_id and v.id=mp.profile_version_id and v.profile_id=pr.id
   join iam.permission_profile_permissions p on p.tenant_id=mp.tenant_id and p.profile_version_id=v.id and p.permission_key=p_permission
  where mp.tenant_id=p_tenant and mp.membership_id=p_membership and mp.is_current
   and m.member_role in ('company_admin','employee') and mp.role_family=case when m.member_role='employee' then 'employee' else 'admin' end
   and pr.role_family=mp.role_family and p_action=any(p.actions)
   and private.scope_matches(p.scope_kind,p.site_id,p.org_unit_id,null,null,p_site,p_org,p_task_kind,p_task)
 )
$$;

-- All authority resets include the new direct/profile/action layers. A suspended
-- account cannot recover forgotten privilege just because status becomes active.
create or replace function private.reset_contract_authorizations() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if old.status is distinct from new.status and (new.status in ('suspended','ended') or old.status in ('suspended','ended')) then
  update iam.member_permission_decisions set status='suspended' where tenant_id=new.tenant_id and membership_id=new.id and status='active';
  update iam.permission_action_grants set status='suspended' where tenant_id=new.tenant_id and membership_id=new.id and status='active';
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and membership_id=new.id and is_current;
 end if;
 if old.member_role is distinct from new.member_role then
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and membership_id=new.id and is_current
   and (new.member_role='company_superadmin' or role_family<>case when new.member_role='employee' then 'employee' else 'admin' end);
 end if;
 return new;
end $$;
create trigger contract_membership_reset after update of status,member_role on iam.memberships
 for each row execute function private.reset_contract_authorizations();

-- No new row is created by these candidate decisions. They remain choices for
-- the owner: subowner scope, baseline contents and invitation snapshot timing.
create table iam.pending_policy_decisions (
 decision_key text primary key,candidate text not null,activated boolean not null default false check(not activated)
);
insert into iam.pending_policy_decisions values
 ('subowner_company_scope','Optional explicit company allowlist',false),
 ('baseline_profile_content','Least privilege templates selected by Superadmin',false),
 ('invitation_profile_version','Pin profile version at invitation issue',false);
revoke all on iam.pending_policy_decisions from public,anon,authenticated,service_role;

revoke all on function private.validate_catalog_actions(),private.functional_action_allowed(uuid,uuid,text,text,uuid,uuid,text,uuid),
 private.reset_contract_authorizations() from public,anon,authenticated,service_role;
commit;
