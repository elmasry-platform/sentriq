-- 050: Reactivating a suspended member restores what the suspension took away.
-- Bug: trigger membership_reactivation_access_reset wiped every role, scope, access row,
-- decision and profile on any non-active -> active change, including suspended -> active.
-- Fix: a snapshot is taken when an active member is suspended. On suspended -> active
-- (same member_role) only rows that changed, are invalid, or did not exist at suspension
-- are taken away. Anything else (ended -> active, invited -> active, role change, no snapshot)
-- keeps the old clean-slate reset. Delegation envelopes are NOT restored here.
create table if not exists iam.membership_suspension_snapshots(
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null,
 membership_id uuid not null references iam.memberships(id) on delete cascade,
 member_role text not null,
 taken_at timestamptz not null default now(),
 taken_by uuid,
 digest jsonb not null,
 decision_ids uuid[] not null default '{}',
 grant_ids uuid[] not null default '{}',
 profile_ids uuid[] not null default '{}',
 status text not null default 'open' check (status in ('open','restored','discarded')),
 closed_at timestamptz,
 closed_by uuid,
 outcome jsonb
);
create unique index if not exists membership_suspension_snapshots_open_uidx
 on iam.membership_suspension_snapshots(tenant_id,membership_id) where status='open';
create index if not exists membership_suspension_snapshots_membership_fk_idx on iam.membership_suspension_snapshots(membership_id);
create index if not exists membership_suspension_snapshots_member_idx
 on iam.membership_suspension_snapshots(tenant_id,membership_id,taken_at desc);
alter table iam.membership_suspension_snapshots enable row level security;
alter table iam.membership_suspension_snapshots force row level security;
revoke all on iam.membership_suspension_snapshots from anon, authenticated, service_role;

create or replace function private.membership_access_digest(p_tenant uuid,p_membership uuid) returns jsonb
language sql stable security definer set search_path='' as $$
 select jsonb_build_object(
  'roles',(select coalesce(jsonb_object_agg(r.id::text,md5(to_jsonb(r)::text)),'{}'::jsonb)
     from iam.membership_roles r where r.tenant_id=p_tenant and r.membership_id=p_membership and r.revoked_at is null),
  'role_sites',(select coalesce(jsonb_object_agg(s.id::text,md5(to_jsonb(s)::text)),'{}'::jsonb)
     from iam.membership_role_sites s join iam.membership_roles r on r.id=s.membership_role_id and r.tenant_id=s.tenant_id
     where r.tenant_id=p_tenant and r.membership_id=p_membership and s.revoked_at is null),
  'role_orgs',(select coalesce(jsonb_object_agg(s.id::text,md5(to_jsonb(s)::text)),'{}'::jsonb)
     from iam.membership_role_org_units s join iam.membership_roles r on r.id=s.membership_role_id and r.tenant_id=s.tenant_id
     where r.tenant_id=p_tenant and r.membership_id=p_membership and s.revoked_at is null),
  'permissions',(select coalesce(jsonb_object_agg(x.id::text,md5(to_jsonb(x)::text)),'{}'::jsonb)
     from iam.member_permissions x where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active),
  'sites',(select coalesce(jsonb_object_agg(x.site_id::text,md5(to_jsonb(x)::text)),'{}'::jsonb)
     from iam.site_access x where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active),
  'orgs',(select coalesce(jsonb_object_agg(x.org_unit_id::text,md5(to_jsonb(x)::text)),'{}'::jsonb)
     from iam.org_unit_access x where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active),
  'tasks',(select coalesce(jsonb_object_agg(x.id::text,md5(to_jsonb(x)::text)),'{}'::jsonb)
     from iam.task_assignments x where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active));
$$;
revoke all on function private.membership_access_digest(uuid,uuid) from public, anon, authenticated, service_role;

create or replace function private.take_membership_suspension_snapshot() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if old.status='active' and new.status='suspended' then
  update iam.membership_suspension_snapshots set status='discarded',closed_at=now(),closed_by=auth.uid()
   where tenant_id=old.tenant_id and membership_id=old.id and status='open';
  insert into iam.membership_suspension_snapshots(tenant_id,membership_id,member_role,taken_at,taken_by,digest,decision_ids,grant_ids,profile_ids)
  values(old.tenant_id,old.id,old.member_role,clock_timestamp(),auth.uid(),private.membership_access_digest(old.tenant_id,old.id),
   coalesce((select array_agg(d.id) from iam.member_permission_decisions d where d.tenant_id=old.tenant_id and d.membership_id=old.id and d.status='active'),'{}'),
   coalesce((select array_agg(g.id) from iam.permission_action_grants g where g.tenant_id=old.tenant_id and g.membership_id=old.id and g.status='active'),'{}'),
   coalesce((select array_agg(p.id) from iam.membership_permission_profiles p where p.tenant_id=old.tenant_id and p.membership_id=old.id and p.is_current),'{}'));
 end if;
 return new;
end $$;
revoke all on function private.take_membership_suspension_snapshot() from public, anon, authenticated, service_role;
drop trigger if exists a_membership_suspension_snapshot on iam.memberships;
create trigger a_membership_suspension_snapshot before update of status on iam.memberships
 for each row execute function private.take_membership_suspension_snapshot();

-- Clean-slate reset (the old behaviour), kept for every path that is not a plain restore.
create or replace function private.wipe_membership_authorizations(p_tenant uuid,p_membership uuid,p_actor uuid) returns void
language plpgsql security definer set search_path='' as $$
declare v_reason text:='Reset on membership reactivation';
begin
 update iam.membership_roles set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where tenant_id=p_tenant and membership_id=p_membership and revoked_at is null;
 update iam.membership_role_sites set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where tenant_id=p_tenant and membership_role_id in (select id from iam.membership_roles where tenant_id=p_tenant and membership_id=p_membership)
   and revoked_at is null;
 update iam.membership_role_org_units set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where tenant_id=p_tenant and membership_role_id in (select id from iam.membership_roles where tenant_id=p_tenant and membership_id=p_membership)
   and revoked_at is null;
 update iam.member_permissions set active=false where tenant_id=p_tenant and membership_id=p_membership and active;
 update iam.site_access set active=false where tenant_id=p_tenant and membership_id=p_membership and active;
 update iam.org_unit_access set active=false where tenant_id=p_tenant and membership_id=p_membership and active;
 update iam.task_assignments set active=false where tenant_id=p_tenant and membership_id=p_membership and active;
end $$;
revoke all on function private.wipe_membership_authorizations(uuid,uuid,uuid) from public, anon, authenticated, service_role;

create or replace function private.restore_membership_access(p_tenant uuid,p_membership uuid,p_snap uuid,p_actor uuid) returns jsonb
language plpgsql security definer set search_path='' as $$
declare s iam.membership_suspension_snapshots%rowtype; v_reason text:='Not restored: changed or invalid after suspension';
 v_dropped int:=0; v_changed int:=0; v_invalid int:=0; v_n int; v_dec int:=0; v_grants int:=0; v_prof int:=0; v_skipped_protected int:=0; v_skipped_invalid int:=0;
begin
 select * into s from iam.membership_suspension_snapshots where id=p_snap;
 -- roles: first rows that changed or were added, then rows that are no longer valid
 update iam.membership_roles r set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where r.tenant_id=p_tenant and r.membership_id=p_membership and r.revoked_at is null
   and s.digest->'roles'->>(r.id::text) is distinct from md5(to_jsonb(r)::text);
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 update iam.membership_roles r set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where r.tenant_id=p_tenant and r.membership_id=p_membership and r.revoked_at is null
   and (not exists(select 1 from iam.roles ro where ro.id=r.role_id and ro.tenant_id=r.tenant_id and ro.active)
    or not exists(select 1 from iam.role_versions v where v.id=r.role_version_id and v.tenant_id=r.tenant_id and v.status='published')
    or not private.decision_source_valid(r.source_delegation_id,r.tenant_id));
 get diagnostics v_n=row_count; v_invalid:=v_invalid+v_n;
 update iam.membership_role_sites x set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where x.tenant_id=p_tenant and x.revoked_at is null
   and x.membership_role_id in (select id from iam.membership_roles where tenant_id=p_tenant and membership_id=p_membership)
   and (s.digest->'role_sites'->>(x.id::text) is distinct from md5(to_jsonb(x)::text)
    or not exists(select 1 from iam.membership_roles r where r.id=x.membership_role_id and r.revoked_at is null));
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 update iam.membership_role_org_units x set revoked_at=now(),revoked_by=p_actor,revoke_reason=v_reason
  where x.tenant_id=p_tenant and x.revoked_at is null
   and x.membership_role_id in (select id from iam.membership_roles where tenant_id=p_tenant and membership_id=p_membership)
   and (s.digest->'role_orgs'->>(x.id::text) is distinct from md5(to_jsonb(x)::text)
    or not exists(select 1 from iam.membership_roles r where r.id=x.membership_role_id and r.revoked_at is null));
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 update iam.member_permissions x set active=false where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active
  and s.digest->'permissions'->>(x.id::text) is distinct from md5(to_jsonb(x)::text);
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 update iam.site_access x set active=false where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active
  and s.digest->'sites'->>(x.site_id::text) is distinct from md5(to_jsonb(x)::text);
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 update iam.org_unit_access x set active=false where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active
  and s.digest->'orgs'->>(x.org_unit_id::text) is distinct from md5(to_jsonb(x)::text);
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 update iam.task_assignments x set active=false where x.tenant_id=p_tenant and x.membership_id=p_membership and x.active
  and s.digest->'tasks'->>(x.id::text) is distinct from md5(to_jsonb(x)::text);
 get diagnostics v_n=row_count; v_changed:=v_changed+v_n;
 -- decisions and action grants that the suspension set to 'suspended'
 update iam.member_permission_decisions d set status='active'
  where d.tenant_id=p_tenant and d.membership_id=p_membership and d.id=any(s.decision_ids)
   and d.status='suspended' and not d.suspended_by_tenant and (d.ends_at is null or d.ends_at>now())
   and private.decision_source_valid(d.source_delegation_id,d.tenant_id)
   and (not d.protected_origin or private.operator_decision_actor() is not null);
 get diagnostics v_dec=row_count;
 select count(*) into v_skipped_protected from iam.member_permission_decisions d
  where d.tenant_id=p_tenant and d.membership_id=p_membership and d.id=any(s.decision_ids) and d.status='suspended'
   and d.protected_origin and private.operator_decision_actor() is null;
 update iam.permission_action_grants g set status='active'
  where g.tenant_id=p_tenant and g.membership_id=p_membership and g.id=any(s.grant_ids)
   and g.status='suspended' and not g.suspended_by_tenant and (g.ends_at is null or g.ends_at>now())
   and private.decision_source_valid(g.source_delegation_id,g.tenant_id);
 get diagnostics v_grants=row_count;
 select (select count(*) from iam.member_permission_decisions d where d.tenant_id=p_tenant and d.membership_id=p_membership
    and d.id=any(s.decision_ids) and d.status='suspended' and not d.protected_origin)
  + (select count(*) from iam.permission_action_grants g where g.tenant_id=p_tenant and g.membership_id=p_membership
    and g.id=any(s.grant_ids) and g.status='suspended') into v_skipped_invalid;
 update iam.membership_permission_profiles p set is_current=true
  where p.tenant_id=p_tenant and p.membership_id=p_membership and p.id=any(s.profile_ids) and not p.is_current
   and private.decision_source_valid(p.source_delegation_id,p.tenant_id)
   and not exists(select 1 from iam.membership_permission_profiles c where c.tenant_id=p.tenant_id and c.membership_id=p.membership_id
     and c.role_family=p.role_family and c.is_current);
 get diagnostics v_prof=row_count;
 return jsonb_build_object('rows_not_restored',v_changed+v_invalid,'not_restored_changed_or_added',v_changed,'not_restored_invalid_role_or_source',v_invalid,'decisions_restored',v_dec,'action_grants_restored',v_grants,
  'profiles_restored',v_prof,'protected_decisions_skipped',v_skipped_protected,'decisions_or_grants_skipped',v_skipped_invalid);
end $$;
revoke all on function private.restore_membership_access(uuid,uuid,uuid,uuid) from public, anon, authenticated, service_role;

create or replace function private.reset_membership_authorizations_on_reactivation() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=coalesce(auth.uid(),new.user_id); s iam.membership_suspension_snapshots%rowtype; v_out jsonb; v_restored boolean:=false; v_have_snap boolean:=false;
begin
 if old.status is distinct from 'active' and new.status='active' then
  select * into s from iam.membership_suspension_snapshots where tenant_id=new.tenant_id and membership_id=new.id and status='open' for update;
  v_have_snap:=found;
  if v_have_snap and old.status='suspended' and s.member_role=new.member_role then
   begin
    v_out:=private.restore_membership_access(new.tenant_id,new.id,s.id,v_actor);
    v_restored:=true;
   exception when others then
    v_out:=jsonb_build_object('restore_failed',sqlstate); v_restored:=false;
   end;
  end if;
  if not v_restored then
   perform private.wipe_membership_authorizations(new.tenant_id,new.id,v_actor);
  end if;
  if v_have_snap then
   update iam.membership_suspension_snapshots set status=case when v_restored then 'restored' else 'discarded' end,
    closed_at=now(),closed_by=v_actor,outcome=coalesce(v_out,'{}'::jsonb)||jsonb_build_object('mode',case when v_restored then 'restored' else 'clean_slate' end)
    where id=s.id;
   insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
   values(new.tenant_id,v_actor,null,'tenant','iam.membership.access_restore','iam.memberships',new.id,
    coalesce(v_out,'{}'::jsonb)||jsonb_build_object('mode',case when v_restored then 'restored' else 'clean_slate' end,'snapshot_id',s.id));
  end if;
 end if;
 return new;
end $$;

-- Members already suspended before this migration: snapshot their current state now.
-- Suspension never touched roles or scopes, so their live rows are exactly what was in force.
insert into iam.membership_suspension_snapshots(tenant_id,membership_id,member_role,digest,decision_ids,grant_ids,profile_ids)
select m.tenant_id,m.id,m.member_role,private.membership_access_digest(m.tenant_id,m.id),
 coalesce((select array_agg(d.id) from iam.member_permission_decisions d where d.tenant_id=m.tenant_id and d.membership_id=m.id and d.status='suspended' and not d.suspended_by_tenant),'{}'),
 coalesce((select array_agg(g.id) from iam.permission_action_grants g where g.tenant_id=m.tenant_id and g.membership_id=m.id and g.status='suspended' and not g.suspended_by_tenant),'{}'),
 '{}'
from iam.memberships m where m.status='suspended'
 and not exists(select 1 from iam.membership_suspension_snapshots x where x.membership_id=m.id and x.status='open');

-- Operator and company report of what the last reactivation did.
create or replace function api.membership_restore_report(p_tenant_id uuid,p_membership_id uuid)
returns table(snapshot_id uuid,mode text,taken_at timestamptz,closed_at timestamptz,outcome jsonb)
language plpgsql stable security definer set search_path='' as $$
begin
 if not (private.can_manage_tenant(p_tenant_id) or private.is_platform_operator()) then
  raise exception 'membership_restore_report_not_allowed' using errcode='42501'; end if;
 return query select s.id,coalesce(s.outcome->>'mode',s.status),s.taken_at,s.closed_at,s.outcome
  from iam.membership_suspension_snapshots s where s.tenant_id=p_tenant_id and s.membership_id=p_membership_id
  order by s.taken_at desc limit 5;
end $$;
revoke all on function api.membership_restore_report(uuid,uuid) from public, anon, service_role;
grant execute on function api.membership_restore_report(uuid,uuid) to authenticated;
