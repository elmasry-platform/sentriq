-- Default-profile publication cannot outlive its delegated source.
begin;
alter table iam.permission_profile_defaults add column source_delegation_id uuid;
alter table iam.permission_profile_defaults add constraint profile_default_source_tenant_fk
 foreign key(tenant_id,source_delegation_id) references iam.delegation_envelopes(tenant_id,id);
create or replace function private.capture_default_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 if session_user='postgres' and current_setting('role')='none' then return new;end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=private.request_actor_id() and status='active';
 if not found then raise exception 'profile_default_actor_required' using errcode='42501';end if;
 new.source_delegation_id:=null;
 if m.member_role<>'company_superadmin' then
  if new.role_family<>'employee' then raise exception 'delegated_defaults_employee_only' using errcode='42501';end if;
  select id into new.source_delegation_id from iam.delegation_envelopes d where tenant_id=new.tenant_id
   and delegate_membership_id=m.id and private.decision_source_valid(d.id,d.tenant_id)
   and 'role_assignment'=any(allowed_capabilities) and level in ('tenant','employees_default')
   order by created_at desc,id limit 1;
  if new.source_delegation_id is null then raise exception 'profile_default_source_required' using errcode='42501';end if;
 end if;
 return new;
end $$;
create trigger profile_default_source_guard before insert or update on iam.permission_profile_defaults
 for each row execute function private.capture_default_source();

-- Invitation acceptance must validate the default's authority, not only the
-- fact that a pointer exists. This preserves current acceptance-time semantics
-- until the owner chooses invitation snapshot timing.
create or replace function private.apply_invitation_phase1_defaults() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_membership uuid;v_family text;v_default record;
begin
 if new.accepted_at is null or old.accepted_at is not null then return new;end if;
 select m.id into v_membership from iam.memberships m where m.tenant_id=new.tenant_id
  and m.user_id=new.accepted_by and m.status='active' and m.member_role=new.intended_level;
 if v_membership is null then raise exception 'accepted_membership_missing' using errcode='23514';end if;
 if new.intended_level='company_superadmin' then
  insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
  select new.tenant_id,v_membership,l.permission_key,l.can_use,l.can_delegate,l.set_by,l.reason
   from iam.superadmin_invitation_limits l where l.tenant_id=new.tenant_id and l.invitation_id=new.id
  on conflict(tenant_id,membership_id,capability_key) do update set can_use=excluded.can_use,can_delegate=excluded.can_delegate,set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
  update iam.superadmin_invitation_limits set invitation_id=null,membership_id=v_membership where tenant_id=new.tenant_id and invitation_id=new.id;
  return new;
 end if;
 v_family:=case when new.intended_level='employee' then 'employee' else 'admin' end;
 select d.profile_id,d.profile_version_id,d.source_delegation_id into v_default from iam.permission_profile_defaults d
 join iam.permission_profiles p on p.tenant_id=d.tenant_id and p.id=d.profile_id and p.active and p.role_family=d.role_family
 join iam.permission_profile_versions v on v.tenant_id=d.tenant_id and v.id=d.profile_version_id and v.profile_id=p.id
 where d.tenant_id=new.tenant_id and d.role_family=v_family
  and private.decision_source_valid(d.source_delegation_id,d.tenant_id);
 if v_default.profile_id is not null then
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and membership_id=v_membership and is_current;
  insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,source,assigned_by,is_current,source_delegation_id)
  values(new.tenant_id,v_membership,v_family,v_default.profile_id,v_default.profile_version_id,'invitation_default',new.invited_by,true,v_default.source_delegation_id);
 end if;
 return new;
end $$;
-- Accept-invitation is trusted service execution: the captured default envelope
-- is validated again, but not replaced with the service actor's own envelope.
create or replace function private.capture_assignment_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;d iam.delegation_envelopes%rowtype;
begin
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id then raise exception 'assignment_source_is_immutable' using errcode='23514';end if;
  return new;
 end if;
 if new.source_delegation_id is not null then
  select * into d from iam.delegation_envelopes where tenant_id=new.tenant_id and id=new.source_delegation_id;
  if not private.decision_source_valid(d.id,d.tenant_id) or not 'role_assignment'=any(d.allowed_capabilities)
   or not exists(select 1 from iam.memberships t where t.tenant_id=new.tenant_id and t.id=new.membership_id
    and (d.level<>'employees_default' or t.member_role='employee')) then
   raise exception 'explicit_assignment_source_invalid' using errcode='42501';end if;
  return new;
 end if;
 if session_user='postgres' and current_setting('role')='none' then return new;end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=private.request_actor_id() and status='active';
 if not found then raise exception 'assignment_actor_required' using errcode='42501';end if;
 if m.member_role<>'company_superadmin' then
  select id into new.source_delegation_id from iam.delegation_envelopes d where tenant_id=new.tenant_id and delegate_membership_id=m.id
   and private.decision_source_valid(d.id,d.tenant_id) and 'role_assignment'=any(allowed_capabilities)
   and (level='tenant' or (level='employees_default' and exists(select 1 from iam.memberships t where t.tenant_id=new.tenant_id and t.id=new.membership_id and t.member_role='employee')))
   order by created_at desc,id limit 1;
  if new.source_delegation_id is null then raise exception 'assignment_source_envelope_required' using errcode='42501';end if;
 end if;
 return new;
end $$;
revoke all on function private.capture_default_source() from public,anon,authenticated,service_role;
commit;
