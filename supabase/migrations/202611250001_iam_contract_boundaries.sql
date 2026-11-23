-- Forward-only IAM contract repair. No deployment or business-data rebuild.
begin;

-- Supabase integration is behind a replaceable identity boundary. A standalone
-- PostgreSQL backend must supply this function from verified, transaction-local
-- identity context, never from client-provided actor identifiers.
create or replace function private.request_actor_id() returns uuid
language sql stable set search_path='' as $$select auth.uid()$$;
revoke all on function private.request_actor_id() from public,anon;
grant execute on function private.request_actor_id() to authenticated,service_role;

drop index if exists iam.one_active_company_superadmin;

alter table iam.member_permission_decisions add column source_delegation_id uuid;
alter table iam.member_permission_decisions add constraint decision_delegation_tenant_fk
 foreign key(tenant_id,source_delegation_id) references iam.delegation_envelopes(tenant_id,id) on delete restrict;

-- Every ancestor is checked synchronously, including expiry, status and actor
-- lifecycle. No cleanup job is needed for an expired root to stop authority.
create or replace function private.decision_source_valid(p_envelope uuid,p_tenant uuid)
returns boolean language sql stable security definer set search_path='' as $$
 with recursive chain as (
  select d.*,array[d.id] as path from iam.delegation_envelopes d where d.id=p_envelope and d.tenant_id=p_tenant
  union all
  select p.*,c.path||p.id from iam.delegation_envelopes p join chain c
   on p.tenant_id=c.tenant_id and p.id=c.parent_envelope_id where not p.id=any(c.path)
 )
 select p_envelope is null or (
  exists(select 1 from chain where parent_envelope_id is null)
  and not exists(select 1 from chain d
   join iam.memberships g on g.tenant_id=d.tenant_id and g.id=d.grantor_membership_id
   join iam.memberships m on m.tenant_id=d.tenant_id and m.id=d.delegate_membership_id
   join core.tenants t on t.id=d.tenant_id
   where d.status<>'active' or d.starts_at>now() or (d.ends_at is not null and now()>=d.ends_at)
    or g.status<>'active' or m.status<>'active' or t.status<>'active'
    or (d.parent_envelope_id is null and g.member_role<>'company_superadmin'))
 )
$$;

-- Delegation administration is itself module-neutral. Module entitlements are
-- checked separately for the exact business permission being administered.
create or replace function private.phase1_can_manage(p_tenant_id uuid,p_capability text,p_target_membership uuid default null,
 p_site_id uuid default null,p_org_unit_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=private.request_actor_id() and m.status='active' and t.status='active'
  and ((m.member_role='company_superadmin' and not exists(select 1 from iam.superadmin_capability_limits l
   where l.tenant_id=m.tenant_id and l.membership_id=m.id and l.capability_key=p_capability and (not l.can_use or not l.can_delegate)))
  or exists(select 1 from iam.delegation_envelopes d where d.tenant_id=m.tenant_id and d.delegate_membership_id=m.id
    and p_capability=any(d.allowed_capabilities) and private.decision_source_valid(d.id,d.tenant_id)
    and private.people_delegation_allows(p_tenant_id,m.id,p_capability,p_target_membership,p_site_id,p_org_unit_id))))
$$;

-- Capture the exact granting envelope. Existing decisions have unknown source;
-- any historical decision by a non-Superadmin enters review rather than being
-- silently trusted as an independent grant.
update iam.member_permission_decisions d set status='suspended'
where d.status='active' and not exists(select 1 from iam.memberships m
 where m.tenant_id=d.tenant_id and m.user_id=d.granted_by and m.member_role='company_superadmin');

create or replace function private.capture_decision_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 -- Offline migration/fixture owner only, never an API/session role.
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id or new.granted_by is distinct from old.granted_by
   or new.membership_id is distinct from old.membership_id or new.tenant_id is distinct from old.tenant_id
   or new.permission_key is distinct from old.permission_key then
   raise exception 'decision_origin_is_immutable' using errcode='23514';
  end if;
  return new;
 end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=new.granted_by and status='active';
 if m.id is null then raise exception 'active_decision_grantor_required' using errcode='42501'; end if;
 if m.member_role<>'company_superadmin' then
  select d.id into new.source_delegation_id from iam.delegation_envelopes d
   where d.tenant_id=new.tenant_id and d.delegate_membership_id=m.id
    and 'direct_permission_decision'=any(d.allowed_capabilities)
    and private.decision_source_valid(d.id,d.tenant_id)
    and (d.level='tenant' or (d.level='employees_default' and exists(select 1 from iam.memberships target
      where target.tenant_id=new.tenant_id and target.id=new.membership_id and target.member_role='employee'))
     or (d.level='site' and new.scope_kind='site' and d.site_id=new.site_id)
     or (d.level='org_unit' and new.scope_kind='org_unit' and d.org_unit_id=new.org_unit_id))
   order by d.created_at desc,d.id limit 1;
  if new.source_delegation_id is null then raise exception 'exact_decision_envelope_required' using errcode='42501'; end if;
 end if;
 return new;
end $$;
create trigger decision_origin_guard before insert or update on iam.member_permission_decisions
 for each row execute function private.capture_decision_source();

-- A revoked/suspended envelope suspends its decisions. Time-based expiry is
-- also enforced above. Adoption creates a new independent, audited decision;
-- original provenance and history are never rewritten.
create or replace function private.suspend_envelope_decisions() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status<>'active' then
  update iam.member_permission_decisions set status='suspended'
   where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
 end if;
 return new;
end $$;
create trigger envelope_decision_suspend after update of status on iam.delegation_envelopes
 for each row execute function private.suspend_envelope_decisions();

create or replace function api.adopt_permission_decision(p_tenant_id uuid,p_decision_id uuid,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare d iam.member_permission_decisions%rowtype; v_id uuid; v_actor uuid:=private.request_actor_id();
begin
 if p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or not private.can_manage_tenant(p_tenant_id) then raise exception 'superadmin_adoption_required' using errcode='42501'; end if;
 select * into d from iam.member_permission_decisions where tenant_id=p_tenant_id and id=p_decision_id for update;
 if not found or d.status='revoked' or d.source_delegation_id is null
  or (d.ends_at is not null and d.ends_at<=now()) or private.decision_source_valid(d.source_delegation_id,d.tenant_id) then
  raise exception 'decision_not_pending_adoption' using errcode='22023'; end if;
 update iam.member_permission_decisions set status='revoked',revoked_at=now(),revoked_by=v_actor,revoke_reason=btrim(p_reason)
  where tenant_id=p_tenant_id and id=p_decision_id;
 insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,org_unit_id,
  task_kind,task_id,can_read,can_write,exception_kind,granted_by,starts_at,ends_at,reason)
 values(d.tenant_id,d.membership_id,d.permission_key,d.decision,d.scope_kind,d.site_id,d.org_unit_id,
  d.task_kind,d.task_id,d.can_read,d.can_write,d.exception_kind,v_actor,greatest(now(),d.starts_at),d.ends_at,btrim(p_reason)) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,d.scope_kind,'iam.permission_decision.adopted','iam.member_permission_decisions',v_id,
  jsonb_build_object('original_decision_id',d.id,'original_envelope_id',d.source_delegation_id,'reason',btrim(p_reason)));
 return v_id;
end $$;

-- Transaction-safe, narrowly-scoped platform account lifecycle. This is not a
-- business-data or role-assignment bypass. Re-activation keeps authorization
-- resets and delegation lifecycle triggers intact.
create or replace function api.platform_set_membership_status(p_tenant_id uuid,p_membership_id uuid,p_status text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
begin
 if not private.is_platform_operator() or p_status not in ('active','suspended','ended')
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_membership_lifecycle_not_authorized' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-membership:'||p_tenant_id::text,0));
 update iam.memberships set status=p_status where tenant_id=p_tenant_id and id=p_membership_id;
 if not found then raise exception 'membership_not_found' using errcode='22023'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.platform.membership_status','iam.memberships',p_membership_id,
  jsonb_build_object('status',p_status,'reason',btrim(p_reason)));
end $$;
create or replace function private.phase1_permission_allowed(p_tenant_id uuid,p_permission_key text,p_site_id uuid default null,
 p_org_unit_id uuid default null,p_write boolean default false,p_task_kind text default null,p_task_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 with actor as (
   select m.id,m.member_role from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and private.has_module_entitlement(p_tenant_id,(select module_key from iam.permission_catalog where permission_key=p_permission_key))
 ), catalog as (
   select pc.permission_key,pc.enabled,pc.feature_key from iam.permission_catalog pc
    where pc.permission_key=p_permission_key 
 ), grants as (
   select rp.scope_kind,null::uuid site_id,null::uuid org_unit_id,mr.id assignment_id,null::text task_kind,null::uuid task_id
   from actor a join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.active
   join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.role_id=mr.role_id and rv.status='published'
   join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=p_permission_key
   where r.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and rv.role_family=r.role_family and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select pp.scope_kind,pp.site_id,pp.org_unit_id,null::uuid,null::text,null::uuid
   from actor a join iam.membership_permission_profiles mp on mp.tenant_id=p_tenant_id and mp.membership_id=a.id and mp.is_current
   join iam.permission_profiles p on p.tenant_id=mp.tenant_id and p.id=mp.profile_id and p.active and p.role_family=mp.role_family
   join iam.permission_profile_versions pv on pv.tenant_id=mp.tenant_id and pv.id=mp.profile_version_id and pv.profile_id=p.id
   join iam.permission_profile_permissions pp on pp.tenant_id=p.tenant_id and pp.profile_version_id=pv.id and pp.permission_key=p_permission_key
   where mp.role_family=case when a.member_role='employee' then 'employee' else 'admin' end
     and (case when p_write then pp.can_write else pp.can_read or pp.can_write end)
   union all
   select d.scope_kind,d.site_id,d.org_unit_id,null::uuid,d.task_kind,d.task_id
   from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='allow' and d.status='active'
     and private.decision_source_valid(d.source_delegation_id,d.tenant_id) and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (case when p_write then d.can_write else d.can_read or d.can_write end)
 ), denies as (
   select d.* from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
     and private.decision_source_valid(d.source_delegation_id,d.tenant_id) and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (d.scope_kind='tenant' or (d.scope_kind='site' and d.site_id=p_site_id)
       or (d.scope_kind='org_unit' and d.org_unit_id=p_org_unit_id)
       or (d.scope_kind='assigned_task' and d.task_kind=p_task_kind and d.task_id=p_task_id))
 )
 select coalesce((select c.enabled and exists(select 1 from actor)
   and (c.feature_key is null or private.has_feature_entitlement(p_tenant_id,(select id from actor),c.feature_key))
   and private.people_scope_allowed(p_tenant_id,(select id from actor),p_site_id,p_org_unit_id)
   and (((select member_role='company_superadmin' from actor)
       and not exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id
         and l.membership_id=(select id from actor) and l.capability_key=p_permission_key and l.can_use=false))
     or exists(select 1 from grants g where g.scope_kind='tenant'
       or (g.scope_kind='site' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_sites rs
          where rs.tenant_id=p_tenant_id and rs.membership_role_id=g.assignment_id and rs.site_id=p_site_id
            and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
         or (g.assignment_id is null and g.site_id=p_site_id)))
       or (g.scope_kind='org_unit' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_org_units ro
          where ro.tenant_id=p_tenant_id and ro.membership_role_id=g.assignment_id and ro.org_unit_id=p_org_unit_id
            and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
         or (g.assignment_id is null and g.org_unit_id=p_org_unit_id)))
       or (g.scope_kind='assigned_task' and (g.assignment_id is not null or (g.task_kind=p_task_kind and g.task_id=p_task_id)) and p_task_id is not null and exists(select 1 from iam.task_assignments ta
          where ta.tenant_id=p_tenant_id and ta.membership_id=(select id from actor) and ta.task_kind=p_task_kind
            and ta.task_id=p_task_id and ta.active and (ta.site_id is null or ta.site_id=p_site_id)
            and (ta.org_unit_id is null or ta.org_unit_id=p_org_unit_id)))))
   and not exists(select 1 from denies d where not exists(
     select 1 from actor a join iam.member_permission_decisions o on o.tenant_id=p_tenant_id and o.membership_id=a.id
     where o.permission_key=p_permission_key and o.decision='allow' and o.exception_kind='specific_override'
       and o.status='active' and o.starts_at<=now() and (o.ends_at is null or now()<o.ends_at)
       and (case when p_write then o.can_write else o.can_read or o.can_write end)
       and private.decision_source_valid(o.source_delegation_id,o.tenant_id)
       and d.scope_kind='tenant' and o.scope_kind in ('site','org_unit','assigned_task')
       and (o.scope_kind<>'site' or o.site_id=p_site_id)
       and (o.scope_kind<>'org_unit' or o.org_unit_id=p_org_unit_id)
       and (o.scope_kind<>'assigned_task' or (o.task_kind=p_task_kind and o.task_id=p_task_id))

   )) from catalog c),false)
$$;


-- Shared grant check: management-category authority is never sufficient to
-- hand out a business permission the actor cannot use or cannot delegate.
create or replace function private.assert_permission_grantable(p_tenant uuid,p_permission text,p_write boolean,p_site uuid,p_org uuid,
 p_task_kind text default null,p_task uuid default null) returns void
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 select * into m from iam.memberships where tenant_id=p_tenant and user_id=private.request_actor_id() and status='active';
 if m.id is null or not private.phase1_permission_allowed(p_tenant,p_permission,p_site,p_org,p_write,p_task_kind,p_task)
  or exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant and l.membership_id=m.id
   and l.capability_key=p_permission and (not l.can_use or not l.can_delegate)) then
  raise exception 'permission_outside_grantor_authority' using errcode='42501';
 end if;
end $$;

create or replace function private.guard_decision_authority() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 -- Offline migration/fixture owner only, never an API/session role.
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if tg_op='INSERT' then
  perform private.assert_permission_grantable(new.tenant_id,new.permission_key,new.can_write,new.site_id,new.org_unit_id,new.task_kind,new.task_id);
 elsif old.decision='deny' and old.status='active' and new.status='revoked'
  and old.granted_by is distinct from private.request_actor_id()
  and not private.can_manage_tenant(old.tenant_id) then
  raise exception 'deny_removal_requires_creator_or_superadmin' using errcode='42501';
 end if;
 return new;
end $$;
create trigger decision_authority_guard before insert or update on iam.member_permission_decisions
 for each row execute function private.guard_decision_authority();

create or replace function private.guard_profile_permission_authority() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 -- Offline migration/fixture owner only, never an API/session role.
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if new.can_read or new.can_write then
 perform private.assert_permission_grantable(new.tenant_id,new.permission_key,new.can_write,new.site_id,new.org_unit_id);
 end if;
 return new;
end $$;
create trigger profile_permission_authority_guard before insert on iam.permission_profile_permissions
 for each row execute function private.guard_profile_permission_authority();

create or replace function private.guard_assigned_role_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare p record;
begin
 -- Offline migration/fixture owner only, never an API/session role.
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if new.role_version_id is not null then
  for p in select * from iam.role_version_permissions where role_version_id=new.role_version_id loop
   if p.scope_kind='tenant' then
    perform private.assert_permission_grantable(new.tenant_id,p.permission_key,p.can_write,null,null);
   end if;
  end loop;
 end if;
 return new;
end $$;
create trigger role_assignment_authority_guard before insert on iam.membership_roles
 for each row execute function private.guard_assigned_role_authority();

create or replace function private.guard_role_binding_authority() returns trigger
language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype; p record; v_site uuid; v_org uuid;
begin
 -- Offline migration/fixture owner only, never an API/session role.
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 select * into a from iam.membership_roles where tenant_id=new.tenant_id and id=new.membership_role_id;
 if tg_table_name='membership_role_sites' then
  v_site:=new.site_id;
  select org_unit_id into v_org from core.sites where tenant_id=new.tenant_id and id=v_site;
 else v_org:=new.org_unit_id; end if;
 for p in select * from iam.role_version_permissions where role_version_id=a.role_version_id
  and scope_kind=case when tg_table_name='membership_role_sites' then 'site' else 'org_unit' end loop
  perform private.assert_permission_grantable(new.tenant_id,p.permission_key,p.can_write,v_site,v_org);
 end loop;
 return new;
end $$;
create trigger role_site_authority_guard before insert on iam.membership_role_sites
 for each row execute function private.guard_role_binding_authority();
create trigger role_org_authority_guard before insert on iam.membership_role_org_units
 for each row execute function private.guard_role_binding_authority();

-- New role versions are invisible to ordinary API DML. Publishing and editing
-- will be exposed through narrow lifecycle operations in the next migration.
alter table iam.role_versions enable row level security;
alter table iam.role_versions force row level security;
alter table iam.role_version_permissions add column tenant_id uuid;
update iam.role_version_permissions p set tenant_id=v.tenant_id from iam.role_versions v where v.id=p.role_version_id;
alter table iam.role_version_permissions alter column tenant_id set not null;
alter table iam.role_version_permissions add constraint role_permission_version_tenant_fk
 foreign key(tenant_id,role_version_id) references iam.role_versions(tenant_id,id) on delete restrict;
create or replace function private.fill_role_permission_tenant() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.tenant_id is null then select tenant_id into new.tenant_id from iam.role_versions where id=new.role_version_id; end if;
 return new;
end $$;
create trigger a_role_permission_tenant before insert on iam.role_version_permissions
 for each row execute function private.fill_role_permission_tenant();
alter table iam.role_version_permissions enable row level security;
alter table iam.role_version_permissions force row level security;
revoke all on iam.role_versions,iam.role_version_permissions from public,anon,authenticated,service_role;
grant select on iam.role_versions,iam.role_version_permissions to authenticated;
create policy role_versions_read on iam.role_versions for select to authenticated using(private.phase1_membership(tenant_id) is not null);
create policy role_version_permissions_read on iam.role_version_permissions for select to authenticated using(private.phase1_membership(tenant_id) is not null);

-- Tenant ownership and membership identity cannot move in place.
create trigger membership_identity_immutable before update on iam.memberships
 for each row execute function private.guard_immutable_fields('tenant_id','user_id');
do $$
declare r record;
begin
 for r in select table_schema,table_name from information_schema.columns
  where column_name='tenant_id' and table_schema in ('core','iam','hse','audit')
  and table_name not in ('tenants') loop
  execute format('create trigger z_contract_tenant_immutable before update of tenant_id on %I.%I for each row execute function private.guard_tenant_id_immutable()',r.table_schema,r.table_name);
 end loop;
end $$;

revoke all on function private.decision_source_valid(uuid,uuid),private.capture_decision_source(),private.suspend_envelope_decisions(),
 private.guard_decision_authority(),private.guard_profile_permission_authority(),private.guard_assigned_role_authority(),private.guard_role_binding_authority(),
 private.assert_permission_grantable(uuid,text,boolean,uuid,uuid,text,uuid),api.adopt_permission_decision(uuid,uuid,text),
 api.platform_set_membership_status(uuid,uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function api.adopt_permission_decision(uuid,uuid,text),api.platform_set_membership_status(uuid,uuid,text,text) to authenticated;
commit;
