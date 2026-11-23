-- Module-neutral action vocabulary and immutable tenant role lifecycle.
begin;
alter table iam.permission_catalog add column supported_actions text[] not null default array['read','write'];
alter table iam.permission_catalog add column supported_scope_kinds text[] not null default array['tenant','site','org_unit','assigned_task'];
alter table iam.permission_catalog add column requires_reason boolean not null default false;
alter table iam.permission_catalog add column is_sensitive boolean not null default false;

-- Explicit action keys keep approve/export/assign separate from generic write.
-- No automatic new actions are granted to any legacy permission.
insert into iam.permission_catalog(permission_key,module_key,label,description,enabled,supported_actions,supported_scope_kinds,is_sensitive,requires_reason) values
 ('iam.roles.manage','core','Manage company roles','Publish versioned functional roles',true,array['publish','assign','revoke'],array['tenant','site','org_unit'],true,true),
 ('iam.profiles.manage','core','Manage company baseline profiles','Apply explicit selected/new target modes',true,array['publish','apply'],array['tenant'],true,true),
 ('iam.decisions.manage','core','Manage permission decisions','Bounded allow and deny administration',true,array['allow','deny','revoke'],array['tenant','site','org_unit','assigned_task'],true,true),
 ('permissions.specific_override','core','Override tenant deny','Exact narrower exception to tenant-wide denial only',true,array['grant'],array['site','org_unit','assigned_task'],true,true);

create table iam.permission_action_grants (
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null,
 membership_id uuid not null,permission_key text not null references iam.permission_catalog(permission_key),
 action_key text not null,scope_kind text not null check(scope_kind in ('tenant','site','org_unit','assigned_task')),
 site_id uuid,org_unit_id uuid,task_kind text,task_id uuid,
 starts_at timestamptz not null default now(),ends_at timestamptz,
 status text not null default 'active' check(status in ('active','suspended','revoked')),
 decision text not null check(decision in ('allow','deny')),
 source_delegation_id uuid,created_by uuid not null references auth.users(id),reason text not null,
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id),
 foreign key(tenant_id,site_id) references core.sites(tenant_id,id),
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id),
 foreign key(tenant_id,source_delegation_id) references iam.delegation_envelopes(tenant_id,id),
 check(ends_at is null or starts_at<ends_at),check(length(btrim(reason)) between 3 and 500),
 check((scope_kind='site')=(site_id is not null)),check((scope_kind='org_unit')=(org_unit_id is not null)),
 check((scope_kind='assigned_task')=(task_id is not null and task_kind is not null)),unique(tenant_id,id)
);
alter table iam.permission_action_grants enable row level security;
alter table iam.permission_action_grants force row level security;
revoke all on iam.permission_action_grants from public,anon,authenticated,service_role;
grant select on iam.permission_action_grants to authenticated;
create policy permission_action_grants_read on iam.permission_action_grants for select to authenticated
 using(membership_id=private.phase1_membership(tenant_id) or private.can_manage_tenant(tenant_id));

create or replace function private.scope_matches(p_kind text,p_site uuid,p_org uuid,p_task_kind text,p_task uuid,
 q_site uuid,q_org uuid,q_task_kind text,q_task uuid) returns boolean
language sql immutable set search_path='' as $$select
 p_kind='tenant' or (p_kind='site' and p_site=q_site) or (p_kind='org_unit' and p_org=q_org)
 or (p_kind='assigned_task' and p_task_kind=q_task_kind and p_task=q_task)$$;

-- This is the stable backend-facing API. Auth integration is confined to
-- request_actor_id(); action semantics and company boundaries remain Postgres.
create or replace function api.authorize(p_tenant_id uuid,p_permission_key text,p_action text,
 p_site_id uuid default null,p_org_unit_id uuid default null,p_task_kind text default null,p_task_id uuid default null)
returns boolean language plpgsql stable security definer set search_path='' as $$
declare m iam.memberships%rowtype; c iam.permission_catalog%rowtype; v_allowed boolean;
begin
 select * into m from iam.memberships where tenant_id=p_tenant_id and user_id=private.request_actor_id() and status='active';
 select * into c from iam.permission_catalog where permission_key=p_permission_key and enabled;
 if m.id is null or c.permission_key is null or not p_action=any(c.supported_actions)
  or not exists(select 1 from core.tenants where id=p_tenant_id and status='active')
  or not private.has_module_entitlement(p_tenant_id,c.module_key)
  or (c.feature_key is not null and not private.has_feature_entitlement(p_tenant_id,m.id,c.feature_key))
  or not private.people_scope_allowed(p_tenant_id,m.id,p_site_id,p_org_unit_id)
  or (p_site_id is not null and not exists(select 1 from core.sites where tenant_id=p_tenant_id and id=p_site_id
    and (p_org_unit_id is null or org_unit_id=p_org_unit_id)))
  or (p_task_id is not null and not exists(select 1 from iam.task_assignments where tenant_id=p_tenant_id
    and membership_id=m.id and task_kind=p_task_kind and task_id=p_task_id and active
    and (site_id is null or site_id=p_site_id) and (org_unit_id is null or org_unit_id=p_org_unit_id))) then return false; end if;
 -- Legacy read/write grants retain only their original explicit meaning.
 if p_action in ('read','write') then
  return private.phase1_permission_allowed(p_tenant_id,p_permission_key,p_site_id,p_org_unit_id,p_action='write',p_task_kind,p_task_id);
 end if;
 if exists(select 1 from iam.member_permission_decisions d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)) then return false; end if;
 if exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)) then return false; end if;
 if m.member_role='company_superadmin' then
  return not exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id
    and l.membership_id=m.id and l.capability_key=p_permission_key and not l.can_use);
 end if;
 return exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='allow' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id));
end $$;

-- Publishing is transactional. Permission rows are inserted while draft, then
-- frozen; users never write version rows directly. Global legacy seeds are not
-- accepted by this company API.
create or replace function private.guard_role_version_content() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_version uuid; v_status text;
begin
 if tg_table_name='role_versions' then
  if tg_op='DELETE' or old.status='published' then
   raise exception 'published_role_version_is_immutable' using errcode='42501'; end if;
 else
  v_version:=case when tg_op='DELETE' then old.role_version_id else new.role_version_id end;
  select status into v_status from iam.role_versions where id=v_version;
  if v_status='published' then raise exception 'published_role_content_is_immutable' using errcode='42501'; end if;
 end if;
 if tg_op='DELETE' then return old; end if;
 return new;
end $$;
create trigger role_version_content_immutable before update or delete on iam.role_versions
 for each row execute function private.guard_role_version_content();
create trigger role_version_permission_immutable before insert or update or delete on iam.role_version_permissions
 for each row execute function private.guard_role_version_content();

create or replace function api.publish_role_version(p_tenant_id uuid,p_role_id uuid,p_permissions jsonb,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_version uuid; v_no integer; r iam.roles%rowtype; p record;
begin
 if not private.phase1_can_manage(p_tenant_id,'role_assignment') or p_reason is null
  or length(btrim(p_reason)) not between 3 and 500 or jsonb_typeof(p_permissions)<>'array'
  or jsonb_array_length(p_permissions) not between 1 and 100 then
  raise exception 'role_publication_not_authorized' using errcode='42501'; end if;
 select * into r from iam.roles where tenant_id=p_tenant_id and id=p_role_id and active for update;
 if not found or r.role_family is null then raise exception 'active_tenant_role_required' using errcode='23514'; end if;
 select coalesce(max(version_no),0)+1 into v_no from iam.role_versions where tenant_id=p_tenant_id and role_id=p_role_id;
 insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by)
 values(p_tenant_id,p_role_id,v_no,r.role_family,'draft',private.request_actor_id()) returning id into v_version;
 for p in select * from jsonb_to_recordset(p_permissions) as x(permission_key text,scope_kind text,can_read boolean,can_write boolean) loop
  if p.scope_kind not in ('tenant','site','org_unit') or p.can_read is null or p.can_write is null or not(p.can_read or p.can_write)
   or not exists(select 1 from iam.permission_catalog c where c.permission_key=p.permission_key and c.enabled and p.scope_kind=any(c.supported_scope_kinds)) then
   raise exception 'invalid_role_permission' using errcode='22023'; end if;
  -- Scoped grants are revalidated against the actual binding on assignment.
  if p.scope_kind='tenant' then perform private.assert_permission_grantable(p_tenant_id,p.permission_key,p.can_write,null,null); end if;
  insert into iam.role_version_permissions(tenant_id,role_version_id,permission_key,scope_kind,can_read,can_write)
  values(p_tenant_id,v_version,p.permission_key,p.scope_kind,p.can_read,p.can_write);
 end loop;
 update iam.role_versions set status='published',published_at=now() where tenant_id=p_tenant_id and id=v_version;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.role_version.published','iam.role_versions',v_version,
  jsonb_build_object('role_id',p_role_id,'version_no',v_no,'reason',btrim(p_reason)));
 return v_version;
end $$;

revoke all on function private.scope_matches(text,uuid,uuid,text,uuid,uuid,uuid,text,uuid),
 private.guard_role_version_content(),api.authorize(uuid,text,text,uuid,uuid,text,uuid),
 api.publish_role_version(uuid,uuid,jsonb,text) from public,anon,authenticated,service_role;
grant execute on function api.authorize(uuid,text,text,uuid,uuid,text,uuid),api.publish_role_version(uuid,uuid,jsonb,text) to authenticated;
commit;
