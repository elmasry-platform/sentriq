-- Delegated role/profile effects retain the source envelope and stop with it.
begin;
alter table iam.membership_roles add column source_delegation_id uuid;
alter table iam.membership_roles add constraint role_assignment_source_tenant_fk
 foreign key(tenant_id,source_delegation_id) references iam.delegation_envelopes(tenant_id,id);
alter table iam.membership_permission_profiles add column source_delegation_id uuid;
alter table iam.membership_permission_profiles add constraint profile_assignment_source_tenant_fk
 foreign key(tenant_id,source_delegation_id) references iam.delegation_envelopes(tenant_id,id);

create or replace function private.capture_assignment_source() returns trigger
language plpgsql security definer set search_path='' as $$
declare m iam.memberships%rowtype;
begin
 if tg_op='UPDATE' then
  if new.source_delegation_id is distinct from old.source_delegation_id then
   raise exception 'assignment_source_is_immutable' using errcode='23514';end if;
  return new;
 end if;
 if session_user='postgres' and current_setting('role')='none' then return new;end if;
 select * into m from iam.memberships where tenant_id=new.tenant_id and user_id=private.request_actor_id() and status='active';
 if not found then raise exception 'assignment_actor_required' using errcode='42501';end if;
 if m.member_role<>'company_superadmin' then
  select d.id into new.source_delegation_id from iam.delegation_envelopes d
   where d.tenant_id=new.tenant_id and d.delegate_membership_id=m.id and private.decision_source_valid(d.id,d.tenant_id)
    and 'role_assignment'=any(d.allowed_capabilities)
    and (d.level='tenant' or (d.level='employees_default' and exists(select 1 from iam.memberships t
      where t.tenant_id=new.tenant_id and t.id=new.membership_id and t.member_role='employee'))
      or (tg_table_name='membership_roles' and d.level in ('site','org_unit')))
   order by d.created_at desc,d.id limit 1;
  if new.source_delegation_id is null then raise exception 'assignment_source_envelope_required' using errcode='42501';end if;
 end if;
 return new;
end $$;
create trigger a_capture_role_source before insert or update on iam.membership_roles
 for each row execute function private.capture_assignment_source();
create trigger a_capture_profile_source before insert or update on iam.membership_permission_profiles
 for each row execute function private.capture_assignment_source();

create or replace function private.suspend_envelope_decisions() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status<>'active' then
  update iam.member_permission_decisions set status='suspended' where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.permission_action_grants set status='suspended' where tenant_id=new.tenant_id and source_delegation_id=new.id and status='active';
  update iam.membership_roles set revoked_at=now(),revoked_by=coalesce(private.request_actor_id(),granted_by),revoke_reason='Source delegation no longer active'
   where tenant_id=new.tenant_id and source_delegation_id=new.id and revoked_at is null;
  update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id and source_delegation_id=new.id and is_current;
 end if;
 return new;
end $$;
revoke all on function private.capture_assignment_source() from public,anon,authenticated,service_role;
commit;
