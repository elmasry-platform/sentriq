-- Tenant-caused role takedowns are reversible; independent revocation is not.
begin;
alter table iam.membership_roles add column suspended_by_tenant boolean not null default false;
alter table iam.membership_roles add constraint role_suspended_by_tenant_consistent
 check (not suspended_by_tenant or (revoked_at is not null and source_delegation_id is not null));
comment on column iam.membership_roles.suspended_by_tenant is
 'Provenance for a company suspension only. Never inferred from historical revoke_reason text.';

create or replace function private.role_tenant_restore_blocker(p_id uuid) returns text
language plpgsql stable security definer set search_path='' as $$
declare r iam.membership_roles%rowtype; m iam.memberships%rowtype; e record;
begin
 select * into r from iam.membership_roles where id=p_id;
 if r.id is null or not r.suspended_by_tenant then return 'not_tenant_suspended'; end if;
 if r.ends_at is not null and r.ends_at<=now() then return 'validity_window_ended'; end if;
 if not private.decision_source_valid(r.source_delegation_id,r.tenant_id) then return 'envelope_not_restored'; end if;
 select * into m from iam.memberships where tenant_id=r.tenant_id and id=r.membership_id;
 if m.status<>'active' or m.member_role='company_superadmin' then return 'membership_inactive_or_changed'; end if;
 if exists(select 1 from hse.people p where p.tenant_id=r.tenant_id and p.membership_id=r.membership_id
   and exists(select 1 from hse.person_engagements x where x.tenant_id=p.tenant_id and x.person_id=p.id)
   and not exists(select 1 from hse.person_engagements x where x.tenant_id=p.tenant_id and x.person_id=p.id
     and x.status='active' and (x.ends_at is null or x.ends_at>now()))) then return 'engagement_ended'; end if;
 if not exists(select 1 from iam.roles rr join iam.role_versions v on v.tenant_id=rr.tenant_id and v.role_id=rr.id
   where rr.tenant_id=r.tenant_id and rr.id=r.role_id and rr.active and v.id=r.role_version_id and v.status='published'
    and v.role_family=case when m.member_role='employee' then 'employee' else 'admin' end) then return 'role_not_assignable'; end if;
 if exists(select 1 from iam.membership_roles o where o.tenant_id=r.tenant_id and o.membership_id=r.membership_id
   and o.role_id=r.role_id and o.id<>r.id and o.revoked_at is null) then return 'conflicting_current_role'; end if;
 -- Scope bindings were not revoked by the tenant cascade, and must not be
 -- resurrected here if an independent cause revoked or expired them.
 if exists(select 1 from iam.membership_role_sites b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id
   and (b.revoked_at is not null or (b.ends_at is not null and b.ends_at<=now())))
 or exists(select 1 from iam.membership_role_org_units b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id
   and (b.revoked_at is not null or (b.ends_at is not null and b.ends_at<=now()))) then return 'scope_binding_ended'; end if;
 for e in with recursive chain as (
   select d.* from iam.delegation_envelopes d where d.tenant_id=r.tenant_id and d.id=r.source_delegation_id
   union all select p.* from iam.delegation_envelopes p join chain c on p.tenant_id=c.tenant_id and p.id=c.parent_envelope_id
 ) select * from chain loop
   if not ('role_assignment'=any(e.allowed_capabilities)) then return 'capability_no_longer_allowed'; end if;
   if exists(select 1 from hse.people p where p.tenant_id=r.tenant_id
     and p.membership_id in (e.grantor_membership_id,e.delegate_membership_id)
     and exists(select 1 from hse.person_engagements x where x.tenant_id=p.tenant_id and x.person_id=p.id)
     and not exists(select 1 from hse.person_engagements x where x.tenant_id=p.tenant_id and x.person_id=p.id
       and x.status='active' and (x.ends_at is null or x.ends_at>now()))) then return 'engagement_ended'; end if;
   if e.level='employees_default' and m.member_role<>'employee' then return 'outside_envelope_scope'; end if;
   if e.level in ('site','org_unit') and (
     exists(select 1 from iam.role_version_permissions p where p.role_version_id=r.role_version_id and p.scope_kind='tenant')
     or (e.level='site' and (not exists(select 1 from iam.membership_role_sites b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id)
       or exists(select 1 from iam.membership_role_sites b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id and b.site_id<>e.site_id)
       or exists(select 1 from iam.membership_role_org_units b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id)))
     or (e.level='org_unit' and (not exists(select 1 from iam.membership_role_org_units b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id)
       or exists(select 1 from iam.membership_role_org_units b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id and b.org_unit_id<>e.org_unit_id)
       or exists(select 1 from iam.membership_role_sites b where b.tenant_id=r.tenant_id and b.membership_role_id=r.id)))
   ) then return 'outside_envelope_scope'; end if;
   if exists(select 1 from iam.superadmin_capability_limits l where l.tenant_id=r.tenant_id and l.membership_id=e.grantor_membership_id
     and (l.capability_key='role_assignment' or exists(select 1 from iam.role_version_permissions p
       where p.role_version_id=r.role_version_id and p.permission_key=l.capability_key))
     and (not l.can_use or not l.can_delegate)) then return 'capability_limit_tightened'; end if;
 end loop;
 return null;
end $$;
revoke all on function private.role_tenant_restore_blocker(uuid) from public,anon,authenticated,service_role;

create or replace function private.guard_membership_role_lifecycle() returns trigger
language plpgsql set search_path='' as $$
begin
 if tg_op='INSERT' then
  if new.suspended_by_tenant then raise exception 'role_suspension_origin_forced' using errcode='23514'; end if;
  return new;
 end if;
 if new.tenant_id is distinct from old.tenant_id or new.membership_id is distinct from old.membership_id
   or new.role_id is distinct from old.role_id or new.starts_at is distinct from old.starts_at or new.granted_by is distinct from old.granted_by
   or (old.ends_at is not null and old.ends_at<=now() and new.ends_at is distinct from old.ends_at) then
  raise exception 'functional role assignment history is immutable' using errcode='23514'; end if;
 if new.suspended_by_tenant and not old.suspended_by_tenant and not (
   old.revoked_at is null and new.revoked_at is not null and pg_trigger_depth()>1
   and current_setting('iam.delegation_tenant_restore',true)='on'
   and exists(select 1 from iam.delegation_envelopes d where d.tenant_id=new.tenant_id and d.id=new.source_delegation_id
     and d.status='suspended' and d.suspended_by_tenant)) then
   raise exception 'role_suspension_origin_forced' using errcode='23514'; end if;
 if old.revoked_at is not null then
  -- Clearing provenance cannot edit any other historical field.
  if old.suspended_by_tenant and not new.suspended_by_tenant and
    to_jsonb(new)-'suspended_by_tenant'=to_jsonb(old)-'suspended_by_tenant' then return new; end if;
  if old.suspended_by_tenant and not new.suspended_by_tenant and new.revoked_at is null and new.revoked_by is null and new.revoke_reason is null
    and pg_trigger_depth()>1 and current_setting('iam.delegation_tenant_restore',true)='on'
    and to_jsonb(new)-array['suspended_by_tenant','revoked_at','revoked_by','revoke_reason']=
        to_jsonb(old)-array['suspended_by_tenant','revoked_at','revoked_by','revoke_reason']
    and private.role_tenant_restore_blocker(old.id) is null then return new; end if;
  raise exception 'functional role assignment history is immutable' using errcode='23514';
 end if;
 return new;
end $$;
create trigger role_suspension_insert_guard before insert on iam.membership_roles
 for each row execute function private.guard_membership_role_lifecycle();

-- A recipient's lifecycle is independent of the assigning delegate's envelope.
create or replace function private.clear_role_tenant_origin_on_membership_change() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status<>'active' or new.member_role is distinct from old.member_role then
  update iam.membership_roles set suspended_by_tenant=false where tenant_id=new.tenant_id and membership_id=new.id and suspended_by_tenant;
 end if;
 return new;
end $$;
create trigger role_tenant_origin_membership after update of status,member_role on iam.memberships
 for each row execute function private.clear_role_tenant_origin_on_membership_change();

create or replace function private.clear_role_tenant_origin_on_engagement_end() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if old.status='active' and (new.status in ('ended','cancelled') or (new.ends_at is not null and new.ends_at<=now()))
   and not exists(select 1 from hse.person_engagements e where e.tenant_id=new.tenant_id and e.person_id=new.person_id
     and e.id<>new.id and e.status='active' and (e.ends_at is null or e.ends_at>now())) then
  update iam.membership_roles r set suspended_by_tenant=false from hse.people p
   where p.tenant_id=new.tenant_id and p.id=new.person_id and r.tenant_id=p.tenant_id
     and r.membership_id=p.membership_id and r.suspended_by_tenant;
 end if;
 return new;
end $$;
create trigger role_tenant_origin_engagement after update of status,ends_at on hse.person_engagements
 for each row execute function private.clear_role_tenant_origin_on_engagement_end();
revoke all on function private.clear_role_tenant_origin_on_membership_change(),private.clear_role_tenant_origin_on_engagement_end()
 from public,anon,authenticated,service_role;

create or replace function private.suspend_envelope_decisions() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status<>'active' then
  update iam.member_permission_decisions set status='suspended',suspended_by_tenant=new.suspended_by_tenant
   where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.permission_action_grants set status='suspended',suspended_by_tenant=new.suspended_by_tenant
   where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.membership_roles set suspended_by_tenant=new.suspended_by_tenant,revoked_at=now(),revoked_by=coalesce(private.request_actor_id(),granted_by),
   revoke_reason=case when new.suspended_by_tenant then 'Source delegation suspended by company suspension'
     else 'Source delegation no longer active' end
   where tenant_id=new.tenant_id and source_delegation_id=new.id and revoked_at is null;
  update iam.membership_permission_profiles set is_current=false,suspended_by_tenant=new.suspended_by_tenant
   where tenant_id=new.tenant_id and source_delegation_id=new.id and is_current;
  if not new.suspended_by_tenant then
   update iam.membership_roles set suspended_by_tenant=false
    where tenant_id=new.tenant_id and source_delegation_id=new.id and suspended_by_tenant;
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
declare v_restored uuid[]; v_role record; v_blocker text;
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
   -- Role restore runs after envelope/effect restore, using its own provenance.
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
   -- Lock candidates in deterministic order. Skips are terminal for this
   -- suspension cycle, not a queued grant if authority is loosened later.
   for v_role in select rr.* from iam.membership_roles rr where rr.tenant_id=new.id and rr.suspended_by_tenant
     order by rr.id for update loop
    v_blocker:=case when v_role.source_delegation_id=any(v_restored)
      then private.role_tenant_restore_blocker(v_role.id) else 'envelope_not_restored' end;
    if v_blocker is null then
     update iam.membership_roles set revoked_at=null,revoked_by=null,revoke_reason=null,suspended_by_tenant=false where id=v_role.id;
    else
     update iam.membership_roles set suspended_by_tenant=false where id=v_role.id;
    end if;
    insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
     values(new.id,private.request_actor_id(),'tenant',case when v_blocker is null then 'iam.delegation_source.restored'
       else 'iam.delegation_source.restore_skipped' end,'iam.membership_roles',v_role.id,
       jsonb_build_object('cause','tenant_reactivation','envelope_id',v_role.source_delegation_id,
         'restored',case when v_blocker is null then 'role_assignment' end,
         'skipped',case when v_blocker is not null then 'role_assignment' end,'reason',v_blocker));
   end loop;
   perform set_config('iam.delegation_tenant_restore','off',true);
 end if;
 return new;
end $$;

create or replace function api.revoke_role_assignment(p_tenant_id uuid,p_assignment_id uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype;b record;
begin
 select * into a from iam.membership_roles where tenant_id=p_tenant_id and id=p_assignment_id for update;
 if not found or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'invalid_assignment_revocation' using errcode='22023';end if;
 if exists(select 1 from iam.role_version_permissions p where p.role_version_id=a.role_version_id and p.scope_kind='tenant')
  and not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id) then
  raise exception 'assignment_revocation_outside_envelope' using errcode='42501';end if;
 for b in select site_id from iam.membership_role_sites where tenant_id=p_tenant_id and membership_role_id=a.id and revoked_at is null loop
  if not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id,b.site_id,null) then
   raise exception 'assignment_revocation_outside_site' using errcode='42501';end if;
 end loop;
 for b in select org_unit_id from iam.membership_role_org_units where tenant_id=p_tenant_id and membership_role_id=a.id and revoked_at is null loop
  if not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id,null,b.org_unit_id) then
   raise exception 'assignment_revocation_outside_org' using errcode='42501';end if;
 end loop;
 if not private.can_manage_tenant(p_tenant_id) and not private.phase1_can_manage(p_tenant_id,'role_assignment',a.membership_id) then
  raise exception 'assignment_revocation_not_authorized' using errcode='42501';end if;
 if a.suspended_by_tenant then
  update iam.membership_roles set suspended_by_tenant=false where tenant_id=p_tenant_id and id=a.id;
 elsif a.revoked_at is null then
 update iam.membership_roles set revoked_at=coalesce(revoked_at,now()),revoked_by=coalesce(revoked_by,private.request_actor_id()),
  revoke_reason=coalesce(revoke_reason,btrim(p_reason)) where tenant_id=p_tenant_id and id=a.id;
 end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.membership_role.revoked','iam.membership_roles',a.id,jsonb_build_object('reason',btrim(p_reason)));
end $$;

commit;
