-- Platform operators (owner, and sub-owners holding the power) can edit a company
-- member's access, including at module level, through one audited RPC. New
-- platform power: member.permissions (owner always; sub-owner by default until
-- the owner withdraws it, like every other power).
-- Also: pending-invitation read and an operator-aware decision trigger path.

insert into iam.platform_permission_catalog(permission_key) values ('member.permissions') on conflict do nothing;

-- Triggers on iam.member_permission_decisions assumed the writer holds a company
-- membership. The audited operator RPC publishes its validated actor in a
-- transaction-local setting; the triggers accept it only for an active operator
-- who currently holds member.permissions. API roles cannot set this GUC.
create or replace function private.operator_decision_actor() returns uuid
language plpgsql stable security definer set search_path='' as $$
declare v uuid:=nullif(current_setting('sentriq.operator_decision_actor',true),'')::uuid;
begin
 if v is not null and exists(select 1 from iam.platform_operators o where o.user_id=v and o.active)
    and private.platform_permission_allowed('member.permissions',v) then return v; end if;
 return null;
end $$;
revoke all on function private.operator_decision_actor() from public,anon,authenticated,service_role;

create or replace function private.guard_decision_authority() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if private.operator_decision_actor() is not null then return new; end if;
 if tg_op='INSERT' then
  perform private.assert_permission_grantable(new.tenant_id,new.permission_key,new.can_write,new.site_id,new.org_unit_id,new.task_kind,new.task_id);
 elsif old.decision='deny' and old.status='active' and new.status='revoked'
  and old.granted_by is distinct from private.request_actor_id()
  and not private.can_manage_tenant(old.tenant_id) then
  raise exception 'deny_removal_requires_creator_or_superadmin' using errcode='42501';
 end if;
 return new;
end $$;

create or replace function private.capture_decision_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 if session_user='postgres' and current_setting('role')='none' then return new; end if;
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id or new.granted_by is distinct from old.granted_by
   or new.membership_id is distinct from old.membership_id or new.tenant_id is distinct from old.tenant_id
   or new.permission_key is distinct from old.permission_key then
   raise exception 'decision_origin_is_immutable' using errcode='23514';
  end if;
  return new;
 end if;
 -- Audited platform-operator path: the grantor is the validated operator, no company envelope.
 if private.operator_decision_actor() is not null and new.granted_by=private.operator_decision_actor() then return new; end if;
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

-- One audited operator edit of a member's access. Targets either explicit catalog
-- keys or a whole module. For company_admin/employee targets it writes tenant-scope
-- allow/deny decisions (or clears them); for a company_superadmin target, whose
-- default is full access, "deny" records a capability limit and default/allow
-- removes it. Module-level access (e.g. HSE off) is p_module_key => 'hse'.
create or replace function api.platform_set_member_access(
 p_tenant_id uuid,p_membership_id uuid,p_choice text,p_reason text,
 p_permission_keys text[] default null,p_module_key text default null
) returns integer language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_target iam.memberships%rowtype; v_keys text[]; v_key text; v_n integer:=0;
        c iam.permission_catalog%rowtype;
begin
 if v_actor is null or not private.is_platform_operator() or not private.platform_permission_allowed('member.permissions')
  or p_choice not in ('default','allow','deny') or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or ((p_permission_keys is null or cardinality(p_permission_keys)=0) = (p_module_key is null)) then
  raise exception 'platform_member_access_not_authorized' using errcode='42501';
 end if;
 if not exists(select 1 from core.tenants where id=p_tenant_id and status='active') then
  raise exception 'platform_member_access_tenant_inactive' using errcode='22023'; end if;
 select * into v_target from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and status='active';
 if v_target.id is null or v_target.user_id=v_actor then
  raise exception 'platform_member_access_target_invalid' using errcode='22023'; end if;
 select coalesce(array_agg(permission_key order by permission_key),'{}') into v_keys from iam.permission_catalog
  where enabled and ((p_module_key is not null and module_key=p_module_key)
    or (p_permission_keys is not null and permission_key=any(p_permission_keys)));
 if cardinality(v_keys)=0 or (p_permission_keys is not null and cardinality(v_keys)<>cardinality(array(select distinct unnest(p_permission_keys)))) then
  raise exception 'platform_member_access_unknown_permission' using errcode='22023'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-operator-access:'||p_tenant_id::text||':'||p_membership_id::text,0));
 perform set_config('sentriq.operator_decision_actor',v_actor::text,true);
 foreach v_key in array v_keys loop
  select * into c from iam.permission_catalog where permission_key=v_key;
  if v_target.member_role='company_superadmin' then
   if p_choice='deny' then
    insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
     values(p_tenant_id,p_membership_id,v_key,false,false,v_actor,btrim(p_reason))
     on conflict(tenant_id,membership_id,capability_key) do update set can_use=false,can_delegate=false,
      set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
   else
    delete from iam.superadmin_capability_limits where tenant_id=p_tenant_id and membership_id=p_membership_id and capability_key=v_key;
   end if;
  else
   if p_choice='allow' and (not private.has_module_entitlement(p_tenant_id,c.module_key)
     or (c.feature_key is not null and not private.has_feature_entitlement(p_tenant_id,p_membership_id,c.feature_key))) then
    raise exception 'permission_feature_not_enabled' using errcode='42501'; end if;
   update iam.member_permission_decisions set status='revoked',revoked_at=now(),revoked_by=v_actor,
     revoke_reason='Replaced by platform operator decision'
    where tenant_id=p_tenant_id and membership_id=p_membership_id and permission_key=v_key
      and scope_kind='tenant' and status='active';
   if p_choice in ('allow','deny') then
    insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,
      status,granted_by,reason)
     values(p_tenant_id,p_membership_id,v_key,p_choice,'tenant',p_choice='allow',p_choice='allow','active',v_actor,btrim(p_reason));
   end if;
  end if;
  v_n:=v_n+1;
 end loop;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,v_actor,'tenant','iam.platform.member_access.set','iam.memberships',p_membership_id,
  jsonb_build_object('choice',p_choice,'module_key',p_module_key,'permission_keys',to_jsonb(v_keys),
   'target_role',v_target.member_role,'reason',btrim(p_reason)));
 return v_n;
end $$;

create or replace function api.company_pending_invitations(p_tenant_id uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb;
begin
 if auth.uid() is null or not (private.can_manage_tenant(p_tenant_id) or private.is_platform_operator()) then
  raise exception 'invitation_read_not_authorized' using errcode='42501'; end if;
 select coalesce(jsonb_agg(to_jsonb(p) order by p.created_at desc),'[]'::jsonb) into v_rows from (
  select i.id,i.email,i.intended_level,i.created_at,i.expires_at from iam.invitations i
   where i.tenant_id=p_tenant_id and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()
   order by i.created_at desc limit 100) p;
 return jsonb_build_object('rows',v_rows);
end $$;

create or replace function api.platform_revoke_invitation(p_invitation_id uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare v_tenant uuid;
begin
 if auth.uid() is null or not private.is_platform_operator() or not private.platform_permission_allowed('superadmin.invite')
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_invitation_revoke_not_authorized' using errcode='42501'; end if;
 update iam.invitations set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=btrim(p_reason)
  where id=p_invitation_id and accepted_at is null and revoked_at is null returning tenant_id into v_tenant;
 if v_tenant is null then raise exception 'invitation_not_found_or_final' using errcode='22023'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(v_tenant,auth.uid(),'tenant','iam.platform.invitation.revoked','iam.invitations',p_invitation_id,jsonb_build_object('reason',btrim(p_reason)));
end $$;

revoke all on function api.platform_set_member_access(uuid,uuid,text,text,text[],text),
 api.company_pending_invitations(uuid),api.platform_revoke_invitation(uuid,text) from public,anon,service_role;
grant execute on function api.platform_set_member_access(uuid,uuid,text,text,text[],text),
 api.company_pending_invitations(uuid),api.platform_revoke_invitation(uuid,text) to authenticated;
