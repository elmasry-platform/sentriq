-- 041: Invitations for operators and companies, with name and initial access.
--
-- DRAFT FOR REVIEW. Not applied to any database.
--
--  * Fixes api.create_company_invitation: it no longer hardcodes the 'hse' module.
--    The inviter must be an active Superadmin whose own live entitlements include at
--    least one catalog module (member-aware, as the 040 review required). A company
--    Superadmin invites Employees only.
--  * Adds api.platform_create_invitation: Owner or Sub-owner (power superadmin.invite)
--    invites any person to any active company at any level.
--  * An invitation now carries the invitee's name and an initial access set
--    (explicit Allow or Deny decisions on catalog permissions). It is applied when the
--    invitation is accepted, never before, and never by the invitee's own authority:
--      - company origin: granted_by = the Superadmin, ordinary (non-protected) decisions,
--        Superadmin power limits respected, Allow only for what the Superadmin could
--        allow today. No personal entitlement exceptions can be created this way.
--      - platform origin: granted_by = the operator, protected_origin (only operators can
--        change them afterwards), Allow is still checked against the member's entitlement.
--    The inviter's authority is re-checked at acceptance: if it is gone, Allows are
--    skipped and only Denies (which only restrict) are applied; both outcomes are audited.
--    The decisions are written by the AFTER UPDATE OF accepted_at trigger on iam.invitations
--    (private.apply_invitation_initial_access), which runs after the membership exists.
--  * Adds api.accept_my_invitation(token) for a signed-in user (verified email must match),
--    so no service-role key is needed. api.accept_invitation stays service_role only.
--  * Adds api.list_invitations (never returns token hashes) and lets operators revoke.
--  * No email is sent. The raw token is returned once at creation, for copy-link use.

alter table iam.invitations
  add column invitee_name text check (invitee_name is null or length(btrim(invitee_name)) between 1 and 200),
  add column initial_decisions jsonb not null default '[]'::jsonb
    check (jsonb_typeof(initial_decisions)='array' and jsonb_array_length(initial_decisions)<=100),
  add column decision_reason text check (decision_reason is null or length(btrim(decision_reason)) between 3 and 500),
  add column origin text not null default 'company' check (origin in ('company','platform'));

-- Validates and normalises [{permission_key, decision}] against the enabled catalog.
create or replace function private.normalize_invitation_decisions(p_decisions jsonb)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare v jsonb;
begin
 if p_decisions is null or jsonb_typeof(p_decisions)<>'array' or jsonb_array_length(p_decisions)>100 then
   raise exception 'invitation_decisions_invalid' using errcode='22023'; end if;
 if exists(select 1 from jsonb_array_elements(p_decisions) e(value)
    where jsonb_typeof(e.value)<>'object' or exists(select 1 from jsonb_object_keys(e.value) k(key) where k.key not in ('permission_key','decision'))) then
   raise exception 'invitation_decisions_invalid' using errcode='22023'; end if;
 if exists(select 1 from jsonb_to_recordset(p_decisions) x(permission_key text,decision text)
    where x.decision is null or x.decision not in ('allow','deny')
       or not exists(select 1 from iam.permission_catalog pc where pc.permission_key=x.permission_key and pc.enabled)) then
   raise exception 'permission_key_not_in_enabled_catalog' using errcode='22023'; end if;
 if (select count(*) from jsonb_to_recordset(p_decisions) x(permission_key text,decision text))
    <> (select count(distinct x.permission_key) from jsonb_to_recordset(p_decisions) x(permission_key text,decision text)) then
   raise exception 'invitation_decisions_duplicate_key' using errcode='22023'; end if;
 select coalesce(jsonb_agg(jsonb_build_object('permission_key',x.permission_key,'decision',x.decision) order by x.permission_key),'[]'::jsonb)
   into v from jsonb_to_recordset(p_decisions) x(permission_key text,decision text);
 return v;
end $$;

-- Superadmin power limits (iam.superadmin_capability_limits) block a capability or a single
-- permission key when the Superadmin may not use or may not delegate it.
create or replace function private.superadmin_limited(p_tenant_id uuid,p_membership_id uuid,p_key text)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=p_tenant_id and l.membership_id=p_membership_id
   and l.capability_key=p_key and (not l.can_use or not l.can_delegate)) $$;

-- Shared insert: duplicate and pending checks, token, row. Callers authorise first.
create or replace function private.insert_invitation(p_tenant_id uuid,p_email text,p_name text,p_level text,p_ttl interval,
  p_decisions jsonb,p_reason text,p_origin text,p_actor uuid)
returns table(invitation_id uuid, token text) language plpgsql security definer set search_path='' as $$
declare v_token text:=encode(extensions.gen_random_bytes(32),'hex'); v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if nullif(btrim(p_reason),'') is not null and length(btrim(p_reason)) not between 3 and 500 then
   raise exception 'invitation_reason_invalid' using errcode='22023'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-invitation:'||p_tenant_id::text||':'||v_email,0));
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.email=v_email and m.status='active') then
   raise exception 'active_membership_already_exists' using errcode='23505'; end if;

 with gone as (update iam.invitations set revoked_at=now(),revoked_by=p_actor,revoke_reason='Expired before reinvitation'
  where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null and expires_at<=now() returning id)
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  select p_tenant_id,p_actor,'tenant','iam.invitation.revoked','iam.invitations',gone.id,jsonb_build_object('reason','Expired before reinvitation','automatic',true) from gone;
 if exists(select 1 from iam.invitations where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null) then
   raise exception 'invitation_already_pending' using errcode='23505'; end if;
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at,invitee_name,initial_decisions,decision_reason,origin)
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),p_level,p_actor,now()+p_ttl,nullif(btrim(p_name),''),p_decisions,nullif(btrim(p_reason),''),p_origin)
 returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,p_actor,'tenant','iam.invitation.created','iam.invitations',v_id,
   jsonb_build_object('email',v_email,'level',p_level,'origin',p_origin,'decision_count',jsonb_array_length(p_decisions),'reason',nullif(btrim(p_reason),'')));
 return query select v_id,v_token;
end $$;

drop function api.create_company_invitation(uuid,text,text,interval);
create function api.create_company_invitation(p_tenant_id uuid,p_email text,p_level text,p_ttl interval default '7 days',
  p_name text default null,p_decisions jsonb default '[]'::jsonb,p_reason text default null)
returns table(invitation_id uuid, token text) language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_email text:=lower(btrim(p_email)); v_member uuid; v_dec jsonb;
begin
 select m.id into v_member from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.member_role='company_superadmin' and m.status='active' and t.status='active';
 if v_actor is null or v_member is null or p_level is distinct from 'employee' or v_email is null or length(v_email)<3 or length(v_email)>254
   or p_ttl is null or p_ttl<=interval '0' or p_ttl>interval '30 days'
   or (p_name is not null and length(btrim(p_name)) not between 1 and 200)
   or not exists(select 1 from (select distinct module_key from iam.permission_catalog where enabled) c
        where private.has_member_module_entitlement(p_tenant_id,v_member,c.module_key)) then
   raise exception 'company_invitation_not_allowed' using errcode='42501';
 end if;
 v_dec:=private.normalize_invitation_decisions(p_decisions);
 if jsonb_array_length(v_dec)>0 then
   if p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
     raise exception 'invitation_reason_required' using errcode='22023'; end if;
   if not private.phase1_can_manage(p_tenant_id,'direct_permission_decision') then
     raise exception 'direct_permission_decision_not_delegated' using errcode='42501'; end if;
   if exists(select 1 from jsonb_to_recordset(v_dec) x(permission_key text,decision text)
       where private.superadmin_limited(p_tenant_id,v_member,x.permission_key)) then
     raise exception 'permission_limited_for_inviter' using errcode='42501'; end if;
   -- A Superadmin can only Allow what they hold themselves, and never create an exception.
   if exists(select 1 from jsonb_to_recordset(v_dec) x(permission_key text,decision text)
       join iam.permission_catalog pc on pc.permission_key=x.permission_key
       where x.decision='allow' and not (private.has_member_module_entitlement(p_tenant_id,v_member,pc.module_key)
         and (pc.feature_key is null or private.has_feature_entitlement(p_tenant_id,v_member,pc.feature_key)))) then
     raise exception 'permission_not_entitled_for_inviter' using errcode='42501'; end if;
 end if;
 return query select * from private.insert_invitation(p_tenant_id,v_email,p_name,p_level,p_ttl,v_dec,p_reason,'company',v_actor);
end $$;

create function api.platform_create_invitation(p_tenant_id uuid,p_email text,p_name text,p_level text,p_ttl interval,
  p_decisions jsonb,p_reason text)
returns table(invitation_id uuid, token text) language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_email text:=lower(btrim(p_email)); v_dec jsonb;
begin
 if v_actor is null or not private.is_platform_operator() or not private.platform_permission_allowed('superadmin.invite')
   or p_level is null or p_level not in ('company_superadmin','company_admin','employee')
   or v_email is null or length(v_email)<3 or length(v_email)>254
   or p_ttl is null or p_ttl<=interval '0' or p_ttl>interval '30 days'
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or (p_name is not null and length(btrim(p_name)) not between 1 and 200)
   or not exists(select 1 from core.tenants t where t.id=p_tenant_id and t.status='active') then
   raise exception 'platform_invitation_not_allowed' using errcode='42501';
 end if;
 v_dec:=private.normalize_invitation_decisions(coalesce(p_decisions,'[]'::jsonb));
 if jsonb_array_length(v_dec)>0 and not private.platform_permission_allowed('member.permissions') then
   raise exception 'platform_invitation_not_allowed' using errcode='42501'; end if;
 -- Superadmin power limits use their own mechanism (create_company_superadmin_invitation).
 if p_level='company_superadmin' and jsonb_array_length(v_dec)>0 then
   raise exception 'superadmin_initial_decisions_not_supported' using errcode='22023'; end if;
 return query select * from private.insert_invitation(p_tenant_id,v_email,p_name,p_level,p_ttl,v_dec,p_reason,'platform',v_actor);
end $$;

-- Guards: allow the accept trigger, and only it, to write initial decisions.
create or replace function private.guard_decision_authority() returns trigger language plpgsql security definer set search_path='' as $$
begin
 if private.migration_runner_active() then return new; end if;
 if private.operator_decision_actor() is not null then return new; end if;
 if tg_op='INSERT' and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_initial_decision',true)='on'
  and new.scope_kind='tenant' and new.reason like 'Invitation initial access:%' then return new; end if;
 if tg_op='UPDATE' and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_initial_decision',true)='on'
  and new.status='revoked' and new.revoke_reason like 'Replaced by invitation initial access:%' then return new; end if;
 if tg_op='INSERT' and new.protected_origin then
  raise exception 'protected_origin_requires_operator' using errcode='42501'; end if;
 if tg_op='INSERT' and new.decision='deny' and new.scope_kind='tenant'
  and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_restriction_deny',true)='on'
  and new.reason like 'Superadmin invitation restriction:%' then return new; end if;
 if tg_op='INSERT' then
  perform private.assert_permission_grantable(new.tenant_id,new.permission_key,new.can_write,new.site_id,new.org_unit_id,new.task_kind,new.task_id);
 else
  if new.protected_origin is distinct from old.protected_origin then
   raise exception 'protected_origin_requires_operator' using errcode='42501'; end if;
  if old.protected_origin and (new.status is distinct from old.status or new.decision is distinct from old.decision
     or new.starts_at is distinct from old.starts_at or new.ends_at is distinct from old.ends_at
     or new.can_read is distinct from old.can_read or new.can_write is distinct from old.can_write) then
   raise exception 'operator_decision_requires_operator' using errcode='42501'; end if;
  if old.decision='deny' and old.status='active' and new.status<>'active' then
   if exists(select 1 from iam.memberships m where m.tenant_id=old.tenant_id and m.id=old.membership_id
        and m.user_id=private.request_actor_id()) then
    raise exception 'own_restriction_cannot_be_cleared' using errcode='42501'; end if;
   if private.deny_locked_for(old.id,private.request_actor_id()) then
    raise exception 'deny_removal_requires_setter_subowner_or_owner' using errcode='42501'; end if;
   if old.granted_by is distinct from private.request_actor_id() and not private.can_manage_tenant(old.tenant_id) then
    raise exception 'deny_removal_requires_creator_or_superadmin' using errcode='42501'; end if;
  end if;
 end if;
 return new;
end $$;

create or replace function private.capture_decision_source() returns trigger language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 if private.migration_runner_active() then return new; end if;
 if tg_op='INSERT' and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_initial_decision',true)='on'
  and new.scope_kind='tenant' and new.reason like 'Invitation initial access:%' then return new; end if;
 if tg_op='INSERT' and new.decision='deny' and new.scope_kind='tenant'
  and pg_trigger_depth()>=2 and current_setting('sentriq.invitation_restriction_deny',true)='on'
  and new.reason like 'Superadmin invitation restriction:%' then return new; end if;
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id or new.granted_by is distinct from old.granted_by
   or new.membership_id is distinct from old.membership_id or new.tenant_id is distinct from old.tenant_id
   or new.permission_key is distinct from old.permission_key then
   raise exception 'decision_origin_is_immutable' using errcode='23514';
  end if;
  return new;
 end if;
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

-- Accept: one core for the service-role and the signed-in paths. Also copies the name.
create or replace function private.accept_invitation_core(p_token text,p_auth_user_id uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_inv iam.invitations%rowtype; v_email text; v_membership uuid;
begin
 if p_token is null or length(p_token) not between 32 and 256 or p_auth_user_id is null then
   raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 select lower(btrim(email)) into v_email from auth.users where id=p_auth_user_id and email_confirmed_at is not null;
 if v_email is null or v_email='' then raise exception 'verified_auth_email_required' using errcode='42501'; end if;
 select * into v_inv from iam.invitations where token_hash=extensions.digest(p_token,'sha256') for update;
 if not found or v_inv.accepted_at is not null or v_inv.revoked_at is not null or now()>=v_inv.expires_at or v_inv.email<>v_email then
   raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 if not exists(select 1 from core.tenants t where t.id=v_inv.tenant_id and t.status='active') then
   raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 if exists(select 1 from iam.memberships m where m.tenant_id=v_inv.tenant_id and m.email=v_email and m.user_id<>p_auth_user_id) then
   raise exception 'membership_email_belongs_to_another_user' using errcode='23505'; end if;
 insert into iam.memberships(tenant_id,user_id,member_role,status,email,display_name)
 values(v_inv.tenant_id,p_auth_user_id,v_inv.intended_level,'active',v_email,v_inv.invitee_name)
 on conflict(tenant_id,user_id) do update set member_role=excluded.member_role,status='active',email=excluded.email,
   display_name=coalesce(iam.memberships.display_name,excluded.display_name),updated_at=now()
   where iam.memberships.status in ('invited','ended','suspended')
 returning id into v_membership;
 if v_membership is null then raise exception 'membership_already_active' using errcode='23505'; end if;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
 values(v_inv.tenant_id,p_auth_user_id,v_membership,'tenant','iam.invitation.accepted','iam.memberships',v_membership,
   jsonb_build_object('invitation_id',v_inv.id,'management_level',v_inv.intended_level));
 update iam.invitations set accepted_at=now(),accepted_by=p_auth_user_id where id=v_inv.id;
 return v_membership;
end $$;

create or replace function api.accept_invitation(p_token text,p_auth_user_id uuid)
returns uuid language sql security definer set search_path='' as $$ select private.accept_invitation_core(p_token,p_auth_user_id) $$;

create function api.accept_my_invitation(p_token text)
returns uuid language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null then raise exception 'invitation_invalid_or_expired' using errcode='22023'; end if;
 return private.accept_invitation_core(p_token,auth.uid());
end $$;

-- Initial access is applied by an AFTER UPDATE OF accepted_at trigger, after the membership exists.
create or replace function private.apply_invitation_initial_access() returns trigger language plpgsql security definer set search_path='' as $$
declare v_membership uuid; v_inviter uuid; v_ok boolean; v_applied int:=0; v_skipped jsonb:='[]'::jsonb; x record; pc iam.permission_catalog%rowtype;
        v_why text; v_old iam.member_permission_decisions%rowtype;
begin
 if new.accepted_at is null or old.accepted_at is not null or jsonb_array_length(new.initial_decisions)=0
    or new.intended_level='company_superadmin' then return new; end if;
 select m.id into v_membership from iam.memberships m where m.tenant_id=new.tenant_id and m.user_id=new.accepted_by and m.status='active';
 select i.id into v_inviter from iam.memberships i join core.tenants t on t.id=i.tenant_id where i.tenant_id=new.tenant_id and i.user_id=new.invited_by
   and i.member_role='company_superadmin' and i.status='active' and t.status='active';
 -- Is the inviter still authorised at acceptance? Operator: still an active operator with member.permissions.
 -- Company: still an active Superadmin with the decision capability. Deny only restricts, so authority gates Allow;
 -- per-permission limits gate both.
 v_ok:=case when new.origin='platform' then exists(select 1 from iam.platform_operators o where o.user_id=new.invited_by and o.active
          and private.platform_permission_allowed('member.permissions',new.invited_by))
        else v_inviter is not null and not private.superadmin_limited(new.tenant_id,v_inviter,'direct_permission_decision') end;
 perform set_config('sentriq.invitation_initial_decision','on',true);
 for x in select * from jsonb_to_recordset(new.initial_decisions) d(permission_key text,decision text) loop
   v_why:=null;
   select * into pc from iam.permission_catalog where permission_key=x.permission_key and enabled;
   if pc.permission_key is null then v_why:='not_in_catalog';
   elsif new.origin='company' and v_inviter is not null and private.superadmin_limited(new.tenant_id,v_inviter,x.permission_key) then v_why:='inviter_limited';
   elsif x.decision='allow' and not v_ok then v_why:='inviter_no_longer_authorised';
   elsif x.decision='allow' and not (private.has_member_module_entitlement(new.tenant_id,v_membership,pc.module_key)
        and (pc.feature_key is null or private.has_feature_entitlement(new.tenant_id,v_membership,pc.feature_key))) then v_why:='not_entitled';
   elsif x.decision='allow' and new.origin='company' and not (private.has_member_module_entitlement(new.tenant_id,v_inviter,pc.module_key)
        and (pc.feature_key is null or private.has_feature_entitlement(new.tenant_id,v_inviter,pc.feature_key))) then v_why:='inviter_not_entitled';
   end if;
   if v_why is null then
     select * into v_old from iam.member_permission_decisions d where d.tenant_id=new.tenant_id and d.membership_id=v_membership
       and d.permission_key=x.permission_key and d.scope_kind='tenant' and d.site_id is null and d.org_unit_id is null
       and d.task_kind is null and d.task_id is null and d.status='active';
     if v_old.id is not null and new.origin='company' and (v_old.protected_origin or (v_old.decision='deny' and v_old.granted_by<>new.invited_by)) then
       v_why:='existing_decision_owned_by_someone_else';
     end if;
   end if;
   if v_why is not null then
     v_skipped:=v_skipped||jsonb_build_array(jsonb_build_object('permission_key',x.permission_key,'why',v_why)); continue;
   end if;
   if v_old.id is not null then
     update iam.member_permission_decisions set status='revoked',revoked_at=now(),revoked_by=new.invited_by,
       revoke_reason='Replaced by invitation initial access: '||coalesce(new.decision_reason,'')
      where id=v_old.id;
   end if;
   insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,can_read,can_write,status,granted_by,reason,protected_origin)
   values(new.tenant_id,v_membership,x.permission_key,x.decision,'tenant',x.decision='allow',x.decision='allow','active',new.invited_by,
     left('Invitation initial access: '||coalesce(new.decision_reason,'no reason recorded'),500),new.origin='platform');
   v_applied:=v_applied+1;
 end loop;
 perform set_config('sentriq.invitation_initial_decision','off',true);
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
 values(new.tenant_id,new.invited_by,v_inviter,'tenant','iam.invitation.initial_access.applied','iam.memberships',v_membership,
   jsonb_build_object('invitation_id',new.id,'invitee_membership_id',v_membership,'origin',new.origin,'applied',v_applied,'skipped',v_skipped,'reason',new.decision_reason));
 return new;
end $$;
create trigger invitation_initial_access after update of accepted_at on iam.invitations
 for each row execute function private.apply_invitation_initial_access();

-- Explicit company-Superadmin check for invitation management. Operators pass only through the
-- superadmin.invite power; they never pass through this helper.
create or replace function private.is_company_superadmin_of(p_tenant_id uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.member_role='company_superadmin' and m.status='active' and t.status='active')
$$;
revoke all on function private.is_company_superadmin_of(uuid) from public,anon,authenticated,service_role;

-- Operators can revoke too; every revoke is audited.
create or replace function api.revoke_invitation(p_invitation_id uuid,p_reason text) returns void
language plpgsql security definer set search_path='' as $$
declare v_t uuid;
begin
 update iam.invitations set revoked_at=now(),revoked_by=auth.uid(),revoke_reason=btrim(p_reason)
 where id=p_invitation_id and accepted_at is null and revoked_at is null and length(btrim(coalesce(p_reason,'')))>=3
   and ((private.is_platform_operator() and private.platform_permission_allowed('superadmin.invite')) or private.is_company_superadmin_of(tenant_id))
 returning tenant_id into v_t;
 if v_t is null then raise exception 'invitation_not_found_or_final' using errcode='22023'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(v_t,auth.uid(),'tenant','iam.invitation.revoked','iam.invitations',p_invitation_id,jsonb_build_object('reason',btrim(p_reason)));
end $$;

-- Listing. Operators with superadmin.invite see any company; a Superadmin sees their own.
create function api.list_invitations(p_tenant_id uuid default null,p_status text default null,p_limit int default 100)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare v_op boolean:=private.is_platform_operator() and private.platform_permission_allowed('superadmin.invite');
begin
 if auth.uid() is null or p_limit is null or p_limit not between 1 and 200
    or (p_status is not null and p_status not in ('pending','accepted','expired','revoked'))
    or not (v_op or (p_tenant_id is not null and private.is_company_superadmin_of(p_tenant_id))) then
   raise exception 'invitation_list_not_allowed' using errcode='42501'; end if;
 return jsonb_build_object('rows',coalesce((select jsonb_agg(r order by r.created_at desc) from (
   select i.id,i.tenant_id,t.name as company_name,i.email,i.invitee_name,i.intended_level,i.origin,i.created_at,i.expires_at,
     i.accepted_at,i.revoked_at,i.revoke_reason,i.invited_by,jsonb_array_length(i.initial_decisions) as decision_count,
     case when i.accepted_at is not null then 'accepted' when i.revoked_at is not null then 'revoked'
          when i.expires_at<=now() then 'expired' else 'pending' end as status
   from iam.invitations i join core.tenants t on t.id=i.tenant_id
   where (p_tenant_id is null or i.tenant_id=p_tenant_id)
     and (p_status is null or p_status=case when i.accepted_at is not null then 'accepted' when i.revoked_at is not null then 'revoked'
          when i.expires_at<=now() then 'expired' else 'pending' end)
   order by i.created_at desc limit p_limit) r),'[]'::jsonb));
end $$;

revoke all on function private.normalize_invitation_decisions(jsonb), private.insert_invitation(uuid,text,text,text,interval,jsonb,text,text,uuid),
  private.accept_invitation_core(text,uuid), private.apply_invitation_initial_access(), private.superadmin_limited(uuid,uuid,text) from public,anon,authenticated,service_role;
revoke all on function api.create_company_invitation(uuid,text,text,interval,text,jsonb,text), api.platform_create_invitation(uuid,text,text,text,interval,jsonb,text),
  api.accept_my_invitation(text), api.list_invitations(uuid,text,int), api.revoke_invitation(uuid,text) from public,anon;
grant execute on function api.create_company_invitation(uuid,text,text,interval,text,jsonb,text), api.platform_create_invitation(uuid,text,text,text,interval,jsonb,text),
  api.accept_my_invitation(text), api.list_invitations(uuid,text,int), api.revoke_invitation(uuid,text) to authenticated;
revoke all on function api.accept_invitation(text,uuid) from public,anon,authenticated;
grant execute on function api.accept_invitation(text,uuid) to service_role;
