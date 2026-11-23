begin;
create or replace function private.valid_specific_override(p_tenant uuid,p_membership uuid,p_permission text,
 p_site uuid,p_org uuid,p_task_kind text,p_task uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.member_permission_decisions o where o.tenant_id=p_tenant and o.membership_id=p_membership
  and o.permission_key=p_permission and o.decision='allow' and o.exception_kind='specific_override'
  and o.status='active' and o.starts_at<=now() and (o.ends_at is null or now()<o.ends_at)
  and private.decision_source_valid(o.source_delegation_id,o.tenant_id)
  and o.scope_kind in ('site','org_unit','assigned_task')
  and private.scope_matches(o.scope_kind,o.site_id,o.org_unit_id,o.task_kind,o.task_id,p_site,p_org,p_task_kind,p_task))
$$;
revoke all on function private.valid_specific_override(uuid,uuid,text,uuid,uuid,text,uuid) from public,anon,authenticated,service_role;
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
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)
   and not (d.scope_kind='tenant' and private.valid_specific_override(p_tenant_id,m.id,p_permission_key,p_site_id,p_org_unit_id,p_task_kind,p_task_id))) then return false; end if;
 if exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='deny' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id)
   and not (d.scope_kind='tenant' and private.valid_specific_override(p_tenant_id,m.id,p_permission_key,p_site_id,p_org_unit_id,p_task_kind,p_task_id))) then return false; end if;
 if m.member_role='company_superadmin' then
  return not exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id
    and l.membership_id=m.id and l.capability_key=p_permission_key and not l.can_use);
 end if;
 return private.functional_action_allowed(p_tenant_id,m.id,p_permission_key,p_action,p_site_id,p_org_unit_id,p_task_kind,p_task_id) or exists(select 1 from iam.permission_action_grants d where d.tenant_id=p_tenant_id and d.membership_id=m.id
   and d.permission_key=p_permission_key and d.action_key=p_action and d.decision='allow' and d.status='active'
   and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and private.scope_matches(d.scope_kind,d.site_id,d.org_unit_id,d.task_kind,d.task_id,p_site_id,p_org_unit_id,p_task_kind,p_task_id));
end $$;
commit;
