-- Company reactivation restores exactly what the company suspension took
-- down. User decision (2026-11-23): when a company is suspended and then
-- reactivated, the delegations the suspension took down come straight back.
-- Envelopes (and the decisions, action grants and profiles sourced from them)
-- that were revoked, expired, or suspended for an independent reason
-- (membership lifecycle, engagement end, explicit revoke) stay down.
-- Role assignments sourced from a suspended envelope stay revoked: functional
-- role assignment history is immutable (membership_role_lifecycle_guard), so
-- that piece is fail-closed and each skipped assignment is audited.
begin;

-- Provenance markers for a company-caused takedown. Only the tenant
-- lifecycle trigger (envelopes) and the envelope cascade (sourced effects)
-- may set them, and only while taking the row down.
alter table iam.delegation_envelopes add column suspended_by_tenant boolean not null default false;
alter table iam.delegation_envelopes add constraint delegation_suspended_by_tenant_consistent
 check (not suspended_by_tenant or status='suspended');
comment on column iam.delegation_envelopes.suspended_by_tenant is
 'Set only by the tenant lifecycle trigger when a company suspension takes the envelope down; cleared by the reactivation restore or by any independent lifecycle cause.';

alter table iam.member_permission_decisions add column suspended_by_tenant boolean not null default false;
alter table iam.member_permission_decisions add constraint decision_suspended_by_tenant_consistent
 check (not suspended_by_tenant or status='suspended');
alter table iam.permission_action_grants add column suspended_by_tenant boolean not null default false;
alter table iam.permission_action_grants add constraint grant_suspended_by_tenant_consistent
 check (not suspended_by_tenant or status='suspended');
alter table iam.membership_permission_profiles add column suspended_by_tenant boolean not null default false;
alter table iam.membership_permission_profiles add constraint profile_suspended_by_tenant_consistent
 check (not suspended_by_tenant or not is_current);

-- The action-history guard pins every column except status. The company
-- suspension marker is lifecycle metadata that moves together with status
-- (set on the way down, cleared on restore or on an independent-cause
-- takeover), so it joins status on the allowed side of the diff.
create or replace function private.guard_action_history() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if tg_op='DELETE' then raise exception 'action_history_is_append_only' using errcode='42501'; end if;
 if tg_op='UPDATE' and to_jsonb(new)-'status'-'suspended_by_tenant' is distinct from to_jsonb(old)-'status'-'suspended_by_tenant' then
  raise exception 'action_origin_and_content_immutable' using errcode='23514'; end if;
 if tg_op='UPDATE' and old.status='revoked' and new.status<>'revoked' then
  raise exception 'revoked_action_cannot_reactivate' using errcode='23514'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(new.tenant_id,private.request_actor_id(),new.scope_kind,'iam.action_decision.'||lower(tg_op),'iam.permission_action_grants',new.id,
 jsonb_build_object('status',new.status,'membership_id',new.membership_id,'source_delegation_id',new.source_delegation_id));
 return new;
end $$;

-- The suspended -> active transition stays forbidden except for the gated
-- tenant-restore path, and the provenance marker can only be set by the gated
-- tenant-suspend path. The gate is a transaction-local setting installed by
-- private.revoke_delegations_on_tenant_suspend() around its own writes.
create or replace function private.guard_delegation_envelope() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_grantor iam.memberships%rowtype; v_delegate iam.memberships%rowtype;
        v_parent iam.delegation_envelopes%rowtype; v_cap text;
begin
 if tg_op='UPDATE' and (new.tenant_id is distinct from old.tenant_id
   or new.grantor_membership_id is distinct from old.grantor_membership_id
   or new.delegate_membership_id is distinct from old.delegate_membership_id
   or new.level is distinct from old.level or new.site_id is distinct from old.site_id
   or new.org_unit_id is distinct from old.org_unit_id or new.allowed_capabilities is distinct from old.allowed_capabilities
   or new.parent_envelope_id is distinct from old.parent_envelope_id or new.created_by is distinct from old.created_by) then
   raise exception 'delegation_envelope_identity_is_immutable' using errcode='23514';
 end if;
 if tg_op='UPDATE' then
   if old.status in ('revoked','suspended') and new.status='active'
     and not (old.status='suspended' and old.suspended_by_tenant and not new.suspended_by_tenant
       and current_setting('iam.delegation_tenant_restore',true)='on') then
     raise exception 'delegation_cannot_be_reactivated' using errcode='23514';
   end if;
   if new.suspended_by_tenant and not old.suspended_by_tenant
     and not (old.status='active' and new.status='suspended'
       and current_setting('iam.delegation_tenant_restore',true)='on') then
     raise exception 'delegation_suspension_origin_forced' using errcode='23514';
   end if;
   return new;
 end if;
 if new.suspended_by_tenant then raise exception 'delegation_suspension_origin_forced' using errcode='23514'; end if;
 select * into v_grantor from iam.memberships where tenant_id=new.tenant_id and id=new.grantor_membership_id for key share;
 if not found then raise exception 'delegation_grantor_missing' using errcode='23503'; end if;
 select * into v_delegate from iam.memberships where tenant_id=new.tenant_id and id=new.delegate_membership_id for key share;
 if not found or v_grantor.status<>'active' or v_delegate.status<>'active' or v_delegate.member_role='company_superadmin'
   or not exists(select 1 from core.tenants t where t.id=new.tenant_id and t.status='active') then
   raise exception 'delegation_membership_or_tenant_inactive' using errcode='42501';
 end if;
 if cardinality(new.allowed_capabilities)=0 or array_length(new.allowed_capabilities,1) is distinct from cardinality(new.allowed_capabilities)
   or exists(select 1 from unnest(new.allowed_capabilities) c where c not in ('role_assignment','direct_permission_decision','scope_management','permissions.specific_override')) then
   raise exception 'delegation_capability_invalid' using errcode='22023';
 end if;
 if v_actor is null or new.created_by is distinct from v_actor or v_grantor.user_id is distinct from v_actor then
   raise exception 'delegation_actor_must_be_verified_grantor' using errcode='42501';
 end if;
 if v_grantor.member_role='company_superadmin' then
   if new.parent_envelope_id is not null then raise exception 'superadmin_delegation_has_no_parent' using errcode='23514'; end if;
 else
   if new.parent_envelope_id is null then raise exception 'delegation_parent_required' using errcode='42501'; end if;
   select * into v_parent from iam.delegation_envelopes where tenant_id=new.tenant_id and id=new.parent_envelope_id for key share;
   if not found or v_parent.status<>'active' or v_parent.delegate_membership_id<>new.grantor_membership_id
     or v_parent.starts_at>now() or (v_parent.ends_at is not null and now()>=v_parent.ends_at)
     or new.starts_at<v_parent.starts_at or (v_parent.ends_at is not null and (new.ends_at is null or new.ends_at>v_parent.ends_at))
     or exists(select 1 from unnest(new.allowed_capabilities) c where not (c=any(v_parent.allowed_capabilities)) )
     or not ((v_parent.level='tenant')
       or (v_parent.level='employees_default' and new.level='employees_default')
       or (v_parent.level='site' and new.level='site' and new.site_id=v_parent.site_id)
       or (v_parent.level='org_unit' and new.level='org_unit' and new.org_unit_id=v_parent.org_unit_id)) then
     raise exception 'delegation_exceeds_parent_envelope' using errcode='42501';
   end if;
 end if;
 foreach v_cap in array new.allowed_capabilities loop
   if v_grantor.member_role='company_superadmin' then
     if exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=new.tenant_id
       and l.membership_id=v_grantor.id and l.capability_key=v_cap and (not l.can_use or not l.can_delegate)) then
       raise exception 'superadmin_capability_not_delegable' using errcode='42501';
     end if;
   elsif not private.people_delegation_allows(new.tenant_id,v_grantor.id,v_cap,new.delegate_membership_id,new.site_id,new.org_unit_id) then
     raise exception 'grantor_lacks_delegated_capability' using errcode='42501';
   end if;
 end loop;
 return new;
end $$;

-- An independent lifecycle cause (membership suspend/end, role change,
-- engagement end, explicit revoke) also covers envelopes already suspended by
-- a company suspension: the tree walk clears their company-suspension marker
-- so a later company reactivation cannot launder the independent cause away.
create or replace function private.revoke_delegation_tree(p_tenant_id uuid,p_envelope_id uuid,p_actor_user_id uuid,p_reason text,p_suspended boolean default false)
returns integer language plpgsql security definer set search_path='' as $$
declare v_count integer:=0; v_status text:=case when p_suspended then 'suspended' else 'revoked' end;
begin
 with recursive tree(id) as (
   select p_envelope_id
   union all select child.id from iam.delegation_envelopes child join tree parent
     on child.tenant_id=p_tenant_id and child.parent_envelope_id=parent.id
 ), changed as (
   update iam.delegation_envelopes d set status=v_status,
     suspended_by_tenant=false,
     revoked_by=case when v_status='revoked' then p_actor_user_id else null end,
     revoked_at=case when v_status='revoked' then now() else null end,
     revoke_reason=case when v_status='revoked' then left(p_reason,500) else null end
   where d.tenant_id=p_tenant_id and d.id in(select id from tree)
     and (d.status='active' or (d.status='suspended' and d.suspended_by_tenant))
   returning 1
 ) select count(*) into v_count from changed;
 return v_count;
end $$;

create or replace function private.revoke_delegations_on_membership_change() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_status text; v_reason text; r record;
begin
 if new.member_role is distinct from old.member_role then
   v_status:='revoked'; v_reason:='Membership role changed';
 elsif new.status in ('suspended','ended') then
   v_status:=case when new.status='suspended' then 'suspended' else 'revoked' end;
   v_reason:='Membership became '||new.status;
 else return new;
 end if;
 for r in select d.id from iam.delegation_envelopes d where d.tenant_id=new.tenant_id
   and (d.grantor_membership_id=new.id or d.delegate_membership_id=new.id)
   and (d.status='active' or (d.status='suspended' and d.suspended_by_tenant)) loop
   perform private.revoke_delegation_tree(new.tenant_id,r.id,coalesce(auth.uid(),new.user_id),v_reason,v_status='suspended');
 end loop;
 return new;
end $$;

-- Engagement end is an independent cause even while the company is suspended.
create or replace function private.revoke_delegations_on_engagement_end() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_membership uuid; v_actor uuid;
begin
 if (old.status='active' and new.status in ('ended','cancelled'))
   or (old.status='active' and new.status='active' and new.ends_at is not null and new.ends_at<=now()) then
   select p.membership_id into v_membership from hse.people p
    where p.tenant_id=new.tenant_id and p.id=new.person_id;
   if v_membership is not null and not exists(select 1 from hse.person_engagements e
      where e.tenant_id=new.tenant_id and e.person_id=new.person_id and e.id<>new.id and e.status='active'
        and (e.ends_at is null or e.ends_at>now())) then
     select m.user_id into v_actor from iam.memberships m where m.tenant_id=new.tenant_id and m.id=v_membership;
     perform private.revoke_delegation_tree(new.tenant_id,d.id,coalesce(auth.uid(),v_actor),
       'All linked person engagements ended',false)
     from iam.delegation_envelopes d where d.tenant_id=new.tenant_id
       and (d.status='active' or (d.status='suspended' and d.suspended_by_tenant))
       and (d.grantor_membership_id=v_membership or d.delegate_membership_id=v_membership);
   end if;
 end if;
 return new;
end $$;

-- The envelope cascade carries the company-suspension marker onto the sourced
-- effects it takes down. An independent cause (marker false) clears the
-- marker from effects it already took down, so a later company reactivation
-- cannot launder the independent cause away. Restoration itself is set-based
-- in private.revoke_delegations_on_tenant_suspend(), not here.
create or replace function private.suspend_envelope_decisions() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status<>'active' then
  update iam.member_permission_decisions set status='suspended',suspended_by_tenant=new.suspended_by_tenant
   where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.permission_action_grants set status='suspended',suspended_by_tenant=new.suspended_by_tenant
   where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.membership_roles set revoked_at=now(),revoked_by=coalesce(private.request_actor_id(),granted_by),
   revoke_reason=case when new.suspended_by_tenant then 'Source delegation suspended by company suspension'
     else 'Source delegation no longer active' end
   where tenant_id=new.tenant_id and source_delegation_id=new.id and revoked_at is null;
  update iam.membership_permission_profiles set is_current=false,suspended_by_tenant=new.suspended_by_tenant
   where tenant_id=new.tenant_id and source_delegation_id=new.id and is_current;
  if not new.suspended_by_tenant then
   update iam.member_permission_decisions set suspended_by_tenant=false
    where tenant_id=new.tenant_id and source_delegation_id=new.id and suspended_by_tenant;
   update iam.permission_action_grants set suspended_by_tenant=false
    where tenant_id=new.tenant_id and source_delegation_id=new.id and suspended_by_tenant;
   update iam.membership_permission_profiles set suspended_by_tenant=false
    where tenant_id=new.tenant_id and source_delegation_id=new.id and suspended_by_tenant;
  end if;
 end if;
 return new;
end $$;

create or replace function private.revoke_delegations_on_tenant_suspend() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_restored uuid[];
begin
 if new.status='suspended' and old.status is distinct from new.status then
   perform set_config('iam.delegation_tenant_restore','on',true);
   update iam.delegation_envelopes set status='suspended',suspended_by_tenant=true
    where tenant_id=new.id and status='active';
   perform set_config('iam.delegation_tenant_restore','off',true);
 elsif old.status='suspended' and new.status='active' then
   perform set_config('iam.delegation_tenant_restore','on',true);
   with restored as (
     update iam.delegation_envelopes set status='active',suspended_by_tenant=false
      where tenant_id=new.id and status='suspended' and suspended_by_tenant
        and (ends_at is null or ends_at>now())
      returning id
   )
   select coalesce(array_agg(id),'{}'::uuid[]) into v_restored from restored;
   insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
    select new.id,private.request_actor_id(),'tenant','iam.delegation.restored',
      'iam.delegation_envelopes',r,jsonb_build_object('cause','tenant_reactivation') from unnest(v_restored) r;
   -- Envelopes whose own validity window ended while the company was down are
   -- not restored; drop the marker so later suspend cycles leave them alone.
   update iam.delegation_envelopes set suspended_by_tenant=false
    where tenant_id=new.id and status='suspended' and suspended_by_tenant;
   -- Sourced effects come back with the envelopes that were just restored.
   -- Role assignments are never un-revoked: functional role assignment
   -- history is immutable, so those rows are audited as skipped instead.
   with d as (
     update iam.member_permission_decisions dd set status='active',suspended_by_tenant=false
      where dd.tenant_id=new.id and dd.status='suspended' and dd.suspended_by_tenant
        and dd.source_delegation_id=any(v_restored)
        and (dd.ends_at is null or dd.ends_at>now())
      returning dd.id
   ), g as (
     update iam.permission_action_grants gg set status='active',suspended_by_tenant=false
      where gg.tenant_id=new.id and gg.status='suspended' and gg.suspended_by_tenant
        and gg.source_delegation_id=any(v_restored)
        and (gg.ends_at is null or gg.ends_at>now())
      returning gg.id
   ), p as (
     update iam.membership_permission_profiles pp set is_current=true,suspended_by_tenant=false
      where pp.tenant_id=new.id and not pp.is_current and pp.suspended_by_tenant
        and pp.source_delegation_id=any(v_restored)
        and not exists(select 1 from iam.membership_permission_profiles o
          where o.tenant_id=pp.tenant_id and o.membership_id=pp.membership_id and o.role_family=pp.role_family
            and o.is_current and o.id<>pp.id)
      returning pp.id
   )
   insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
    select new.id,private.request_actor_id(),'tenant','iam.delegation_source.restored',v.record_type,v.record_id,
      jsonb_build_object('cause','tenant_reactivation','envelope_id',v.envelope_id,'restored',v.kind)
    from (
      select 'iam.member_permission_decisions'::text record_type,d.id record_id,dd.source_delegation_id envelope_id,'decision'::text kind
       from d join iam.member_permission_decisions dd on dd.id=d.id
      union all
      select 'iam.permission_action_grants',g.id,gg.source_delegation_id,'grant'
       from g join iam.permission_action_grants gg on gg.id=g.id
      union all
      select 'iam.membership_permission_profiles',p.id,pp.source_delegation_id,'profile'
       from p join iam.membership_permission_profiles pp on pp.id=p.id
    ) v;
   -- Everything the tenant suspension took down that is not coming back gets
   -- an audited skip, then loses its marker.
   insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
    select new.id,private.request_actor_id(),'tenant','iam.delegation_source.restore_skipped',v.record_type,v.record_id,
      jsonb_build_object('cause','tenant_reactivation','envelope_id',v.envelope_id,'skipped',v.kind,'reason',v.reason)
    from (
      select 'iam.member_permission_decisions'::text record_type,dd.id record_id,dd.source_delegation_id envelope_id,
        'decision'::text kind,'validity_window_ended'::text reason
       from iam.member_permission_decisions dd
       where dd.tenant_id=new.id and dd.suspended_by_tenant and dd.status='suspended'
         and dd.source_delegation_id=any(v_restored)
      union all
      select 'iam.permission_action_grants',gg.id,gg.source_delegation_id,'grant','validity_window_ended'
       from iam.permission_action_grants gg
       where gg.tenant_id=new.id and gg.suspended_by_tenant and gg.status='suspended'
         and gg.source_delegation_id=any(v_restored)
      union all
      select 'iam.membership_permission_profiles',pp.id,pp.source_delegation_id,'profile','conflicting_current_profile'
       from iam.membership_permission_profiles pp
       where pp.tenant_id=new.id and pp.suspended_by_tenant and not pp.is_current
         and pp.source_delegation_id=any(v_restored)
      union all
      select 'iam.membership_roles',rr.id,rr.source_delegation_id,'role_assignment','role_assignment_history_immutable'
       from iam.membership_roles rr
       where rr.tenant_id=new.id and rr.revoked_at is not null
         and rr.revoke_reason='Source delegation suspended by company suspension'
         and rr.source_delegation_id=any(v_restored)
      union all
      select 'iam.member_permission_decisions',dd.id,dd.source_delegation_id,'decision','envelope_not_restored'
       from iam.member_permission_decisions dd join iam.delegation_envelopes e
         on e.tenant_id=dd.tenant_id and e.id=dd.source_delegation_id and e.status<>'active'
       where dd.tenant_id=new.id and dd.suspended_by_tenant and dd.status='suspended'
      union all
      select 'iam.permission_action_grants',gg.id,gg.source_delegation_id,'grant','envelope_not_restored'
       from iam.permission_action_grants gg join iam.delegation_envelopes e
         on e.tenant_id=gg.tenant_id and e.id=gg.source_delegation_id and e.status<>'active'
       where gg.tenant_id=new.id and gg.suspended_by_tenant and gg.status='suspended'
      union all
      select 'iam.membership_permission_profiles',pp.id,pp.source_delegation_id,'profile','envelope_not_restored'
       from iam.membership_permission_profiles pp join iam.delegation_envelopes e
         on e.tenant_id=pp.tenant_id and e.id=pp.source_delegation_id and e.status<>'active'
       where pp.tenant_id=new.id and pp.suspended_by_tenant and not pp.is_current
    ) v;
   update iam.member_permission_decisions set suspended_by_tenant=false
    where tenant_id=new.id and suspended_by_tenant;
   update iam.permission_action_grants set suspended_by_tenant=false
    where tenant_id=new.id and suspended_by_tenant;
   update iam.membership_permission_profiles set suspended_by_tenant=false
    where tenant_id=new.id and suspended_by_tenant;
   perform set_config('iam.delegation_tenant_restore','off',true);
 end if;
 return new;
end $$;

commit;
