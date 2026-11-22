-- Phase 1 permission completion. All caller-facing mutations derive identity
-- from auth.uid(); platform authority and company authority are kept separate.
begin;

-- Keep historical unclassified roles editable for review without allowing a
-- NULL family on any new or newly-classified tenant role.
alter table iam.roles add column if not exists phase1_legacy_unclassified boolean not null default false;
update iam.roles set phase1_legacy_unclassified=true
 where tenant_id is not null and role_family is null and not phase1_legacy_unclassified;
alter table iam.roles drop constraint if exists roles_phase1_family_not_null_check;
alter table iam.roles add constraint roles_phase1_family_not_null_check
 check(tenant_id is null or
   (role_family in ('admin','employee') and not phase1_legacy_unclassified) or
   (role_family is null and phase1_legacy_unclassified)) not valid;
alter table iam.roles validate constraint roles_phase1_family_not_null_check;

create or replace function private.guard_role_family_change() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if tg_op='INSERT' and (new.tenant_id is not null and
     (new.role_family is null or new.role_family not in ('admin','employee') or new.phase1_legacy_unclassified)) then
   raise exception 'tenant role requires Admin or Employee family' using errcode='23514';
 end if;
 if tg_op='UPDATE' and new.phase1_legacy_unclassified is distinct from old.phase1_legacy_unclassified then
   if not (old.phase1_legacy_unclassified and not new.phase1_legacy_unclassified
       and new.role_family in ('admin','employee')) then
     raise exception 'legacy role classification can only be cleared with an explicit valid family' using errcode='23514';
   end if;
 end if;
 if new.tenant_id is not null and (new.role_family is null or new.role_family not in ('admin','employee'))
    and not new.phase1_legacy_unclassified then
   raise exception 'tenant role requires Admin or Employee family' using errcode='23514';
 end if;
 if new.role_family is distinct from old.role_family and (
   exists(select 1 from iam.membership_roles mr where mr.tenant_id=old.tenant_id and mr.role_id=old.id)
   or exists(select 1 from iam.role_versions rv where rv.tenant_id=old.tenant_id and rv.role_id=old.id)
 ) then raise exception 'role family is immutable after version or assignment history exists' using errcode='23514'; end if;
 return new;
end $$;
drop trigger if exists role_family_guard on iam.roles;
create trigger role_family_guard before insert or update of role_family,tenant_id,phase1_legacy_unclassified
 on iam.roles for each row execute function private.guard_role_family_change();

-- A separate default pointer is required: a change applied only to selected
-- existing members must not silently become the default for future invitees.
create table iam.permission_profile_defaults (
 tenant_id uuid not null,
 role_family text not null check(role_family in ('admin','employee')),
 profile_id uuid not null,
 profile_version_id uuid not null,
 updated_by uuid not null references auth.users(id) on delete restrict,
 updated_at timestamptz not null default now(),
 primary key(tenant_id,role_family),
 foreign key(tenant_id,profile_id) references iam.permission_profiles(tenant_id,id) on delete restrict,
 foreign key(tenant_id,profile_version_id) references iam.permission_profile_versions(tenant_id,id) on delete restrict
);

-- Task-specific permissions are direct assignment decisions; profiles do not
-- have task columns and therefore may only express tenant/site/org-unit scope.
alter table iam.permission_profile_permissions drop constraint if exists permission_profile_permissions_scope_kind_check;
alter table iam.permission_profile_permissions add constraint permission_profile_permissions_scope_kind_check
 check(scope_kind in ('tenant','site','org_unit')) not valid;
alter table iam.permission_profile_permissions validate constraint permission_profile_permissions_scope_kind_check;

alter table iam.delegation_envelopes add column if not exists parent_envelope_id uuid;
do $$ begin
 if not exists(select 1 from pg_constraint where conrelid='iam.delegation_envelopes'::regclass and conname='delegation_parent_same_tenant_fkey') then
   alter table iam.delegation_envelopes add constraint delegation_parent_same_tenant_fkey
    foreign key(tenant_id,parent_envelope_id) references iam.delegation_envelopes(tenant_id,id) on delete restrict not valid;
 end if;
end $$;
alter table iam.delegation_envelopes validate constraint delegation_parent_same_tenant_fkey;

create table iam.delegation_review_events (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, envelope_id uuid not null,
 actor_user_id uuid not null references auth.users(id) on delete restrict,
 action text not null check(action in ('revoke','extend','confirm_expired','suspend')),
 previous_ends_at timestamptz, new_ends_at timestamptz,
 reason text not null check(length(btrim(reason)) between 3 and 500),
 occurred_at timestamptz not null default now(),
 foreign key(tenant_id,envelope_id) references iam.delegation_envelopes(tenant_id,id) on delete restrict,
 check((action='extend')=(new_ends_at is not null)),
 check(new_ends_at is null or previous_ends_at is distinct from new_ends_at)
);

-- Capability restrictions include both HSE permissions and platform-defined
-- management capabilities, so the legacy permission-catalog FK is too narrow.
alter table iam.superadmin_invitation_limits drop constraint if exists superadmin_invitation_limits_permission_key_fkey;

-- Definer helpers remain non-callable directly; policies/functions invoke them
-- as postgres. Every function pins an empty search_path.
create or replace function private.people_delegation_allows(
 p_tenant_id uuid,p_actor_membership uuid,p_capability text,p_target_membership uuid,
 p_site_id uuid,p_org_unit_id uuid
) returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1 from iam.delegation_envelopes d
   join iam.memberships grantor on grantor.tenant_id=d.tenant_id and grantor.id=d.grantor_membership_id
   join iam.memberships delegate on delegate.tenant_id=d.tenant_id and delegate.id=d.delegate_membership_id
   join core.tenants t on t.id=d.tenant_id
   left join iam.delegation_envelopes parent on parent.tenant_id=d.tenant_id and parent.id=d.parent_envelope_id
   where d.tenant_id=p_tenant_id and d.delegate_membership_id=p_actor_membership
     and d.status='active' and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and t.status='active' and grantor.status='active' and delegate.status='active'
     and delegate.member_role in ('company_admin','employee')
     and p_capability=any(d.allowed_capabilities)
     and ((d.parent_envelope_id is null and grantor.member_role='company_superadmin')
       or (d.parent_envelope_id is not null and parent.status='active' and parent.starts_at<=now()
         and (parent.ends_at is null or now()<parent.ends_at)
         and parent.delegate_membership_id=d.grantor_membership_id
         and p_capability=any(parent.allowed_capabilities)))
     and (p_target_membership is null or p_target_membership=d.delegate_membership_id
       or exists(select 1 from iam.memberships target where target.tenant_id=d.tenant_id and target.id=p_target_membership
         and ((d.level='employees_default' and target.member_role='employee') or d.level='tenant'
           or (d.level='site' and p_site_id=d.site_id and exists(select 1 from iam.site_access sa
             where sa.tenant_id=d.tenant_id and sa.membership_id=target.id and sa.site_id=d.site_id and sa.active))
           or (d.level='org_unit' and p_org_unit_id=d.org_unit_id and exists(select 1 from iam.org_unit_access oa
             where oa.tenant_id=d.tenant_id and oa.membership_id=target.id and oa.org_unit_id=d.org_unit_id and oa.active)))))
     and (d.level='tenant' or d.level='employees_default'
       or (d.level='site' and p_site_id=d.site_id) or (d.level='org_unit' and p_org_unit_id=d.org_unit_id))
     and (d.parent_envelope_id is null or (
       (parent.level='tenant')
       or (parent.level='employees_default' and d.level='employees_default')
       or (parent.level='site' and d.level='site' and d.site_id=parent.site_id)
       or (parent.level='org_unit' and d.level='org_unit' and d.org_unit_id=parent.org_unit_id)))
   )
$$;

create or replace function private.phase1_can_manage(p_tenant_id uuid,p_capability text,p_target_membership uuid default null,
 p_site_id uuid default null,p_org_unit_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
    and private.has_module_entitlement(p_tenant_id,'hse')
     and ((m.member_role='company_superadmin' and not exists(select 1 from iam.superadmin_capability_limits l
       where l.tenant_id=m.tenant_id and l.membership_id=m.id and l.capability_key=p_capability
         and (l.can_delegate=false or l.can_use=false)))
     or private.people_delegation_allows(p_tenant_id,m.id,p_capability,p_target_membership,p_site_id,p_org_unit_id)))
$$;

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
   if old.status in ('revoked','suspended') and new.status='active' then
     raise exception 'delegation_cannot_be_reactivated' using errcode='23514';
   end if;
   return new;
 end if;
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
create trigger delegation_envelope_guard before insert or update on iam.delegation_envelopes
 for each row execute function private.guard_delegation_envelope();

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
     revoked_by=case when v_status='revoked' then p_actor_user_id else null end,
     revoked_at=case when v_status='revoked' then now() else null end,
     revoke_reason=case when v_status='revoked' then left(p_reason,500) else null end
   where d.tenant_id=p_tenant_id and d.id in(select id from tree) and d.status='active'
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
   and (d.grantor_membership_id=new.id or d.delegate_membership_id=new.id) and d.status='active' loop
   perform private.revoke_delegation_tree(new.tenant_id,r.id,coalesce(auth.uid(),new.user_id),v_reason,v_status='suspended');
 end loop;
 return new;
end $$;
create trigger delegation_membership_lifecycle after update of status,member_role on iam.memberships
 for each row when (old.status is distinct from new.status or old.member_role is distinct from new.member_role)
 execute function private.revoke_delegations_on_membership_change();

create or replace function private.revoke_delegations_on_tenant_suspend() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.status='suspended' and old.status is distinct from new.status then
   update iam.delegation_envelopes set status='suspended' where tenant_id=new.id and status='active';
 end if;
 return new;
end $$;
create trigger delegation_tenant_suspend after update of status on core.tenants
 for each row execute function private.revoke_delegations_on_tenant_suspend();

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
     from iam.delegation_envelopes d where d.tenant_id=new.tenant_id and d.status='active'
       and (d.grantor_membership_id=v_membership or d.delegate_membership_id=v_membership);
   end if;
 end if;
 return new;
end $$;
create trigger delegation_engagement_end after update of status,ends_at on hse.person_engagements
 for each row when (old.status is distinct from new.status or old.ends_at is distinct from new.ends_at)
 execute function private.revoke_delegations_on_engagement_end();

create or replace function private.validate_membership_permission_profile() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_profile iam.permission_profiles%rowtype; v_version iam.permission_profile_versions%rowtype; v_member iam.memberships%rowtype;
        v_expected_family text;
begin
 select * into v_profile from iam.permission_profiles where tenant_id=new.tenant_id and id=new.profile_id;
 select * into v_version from iam.permission_profile_versions where tenant_id=new.tenant_id and id=new.profile_version_id;
 select * into v_member from iam.memberships where tenant_id=new.tenant_id and id=new.membership_id;
 v_expected_family:=case when v_member.member_role='employee' then 'employee' else 'admin' end;
 if v_profile.id is null or v_version.id is null or v_member.id is null
   or v_version.profile_id<>v_profile.id or v_member.status<>'active'
   or v_member.member_role='company_superadmin'
   or new.role_family<>v_expected_family
   or new.role_family<>v_profile.role_family then
   raise exception 'membership_profile_assignment_invalid' using errcode='23514';
 end if;
 return new;
end $$;
create trigger membership_permission_profile_guard before insert or update of tenant_id,membership_id,role_family,profile_id,profile_version_id
 on iam.membership_permission_profiles for each row execute function private.validate_membership_permission_profile();

create or replace function private.guard_permission_profile_immutability() returns trigger
language plpgsql set search_path='' as $$
begin
 if tg_op='DELETE' or to_jsonb(new)-array['id'] is distinct from to_jsonb(old)-array['id'] then
   raise exception 'permission_profile_version_content_is_immutable' using errcode='42501';
 end if;
 return new;
end $$;
create trigger permission_profile_version_immutable before update or delete on iam.permission_profile_versions
 for each row execute function private.guard_permission_profile_immutability();
create trigger permission_profile_permission_immutable before update or delete on iam.permission_profile_permissions
 for each row execute function private.guard_permission_profile_immutability();

create or replace function private.guard_delegation_review_immutable() returns trigger
language plpgsql set search_path='' as $$
begin raise exception 'delegation_review_history_is_append_only' using errcode='42501'; end $$;
create trigger delegation_review_immutable before update or delete on iam.delegation_review_events
 for each row execute function private.guard_delegation_review_immutable();

create or replace function private.apply_invitation_phase1_defaults() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_membership uuid; v_family text; v_default record;
begin
 if new.accepted_at is null or old.accepted_at is not null then return new; end if;
 if new.intended_level='company_superadmin' then
   select m.id into v_membership from iam.memberships m where m.tenant_id=new.tenant_id
    and m.user_id=new.accepted_by and m.status='active' and m.member_role='company_superadmin';
   if v_membership is not null then
     insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
     select new.tenant_id,v_membership,l.permission_key,l.can_use,l.can_delegate,l.set_by,l.reason
       from iam.superadmin_invitation_limits l where l.tenant_id=new.tenant_id and l.invitation_id=new.id
     on conflict(tenant_id,membership_id,capability_key) do update set can_use=excluded.can_use,
       can_delegate=excluded.can_delegate,set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
     update iam.superadmin_invitation_limits set invitation_id=null,membership_id=v_membership
       where tenant_id=new.tenant_id and invitation_id=new.id;
   end if;
   return new;
 end if;
 v_family:=case when new.intended_level='employee' then 'employee' else 'admin' end;
 select m.id into v_membership from iam.memberships m where m.tenant_id=new.tenant_id
   and m.user_id=new.accepted_by and m.status='active' and m.member_role=new.intended_level;
 if v_membership is null then return new; end if;
 select d.profile_id,d.profile_version_id into v_default from iam.permission_profile_defaults d
   join iam.permission_profiles p on p.tenant_id=d.tenant_id and p.id=d.profile_id and p.active and p.role_family=d.role_family
   join iam.permission_profile_versions pv on pv.tenant_id=d.tenant_id and pv.id=d.profile_version_id and pv.profile_id=d.profile_id
   where d.tenant_id=new.tenant_id and d.role_family=v_family;
 if v_default.profile_id is not null then
   update iam.membership_permission_profiles set is_current=false where tenant_id=new.tenant_id
     and membership_id=v_membership and role_family=v_family and is_current;
   insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,
      source,assigned_by,is_current)
   values(new.tenant_id,v_membership,v_family,v_default.profile_id,v_default.profile_version_id,
      'invitation_default',new.invited_by,true);
 end if;
 return new;
end $$;
create trigger invitation_phase1_defaults after update of accepted_at on iam.invitations
 for each row execute function private.apply_invitation_phase1_defaults();

-- Company Superadmins may invite Admins and Employees using the signed-in
-- identity. Only Platform Operators may create a Company Superadmin invite;
-- restrictions are captured before the invite is issued and copied at accept.
alter table iam.invitations drop constraint if exists invitations_intended_level_check;
alter table iam.invitations add constraint invitations_intended_level_check
 check(intended_level in ('company_superadmin','company_admin','employee')) not valid;
alter table iam.invitations validate constraint invitations_intended_level_check;

create or replace function api.create_company_invitation(
 p_tenant_id uuid,p_email text,p_level text,p_ttl interval default interval '7 days'
) returns table(invitation_id uuid,token text)
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_token text:=encode(extensions.gen_random_bytes(32),'hex');
        v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if v_actor is null or p_level not in ('company_admin','employee') or v_email is null
   or length(v_email)<3 or length(v_email)>254 or p_ttl is null
   or p_ttl<=interval '0' or p_ttl>interval '30 days'
   or not exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
      where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.member_role='company_superadmin'
        and m.status='active' and t.status='active' and private.has_module_entitlement(p_tenant_id,'hse')) then
   raise exception 'company_invitation_not_allowed' using errcode='42501';
 end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-invitation:'||p_tenant_id::text||':'||v_email,0));
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.email=v_email and m.status='active') then
   raise exception 'active_membership_already_exists' using errcode='23505';
 end if;
 update iam.invitations set revoked_at=now(),revoked_by=v_actor,revoke_reason='Expired before reinvitation'
  where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null and expires_at<=now();
 if exists(select 1 from iam.invitations where tenant_id=p_tenant_id and email=v_email
    and accepted_at is null and revoked_at is null) then
   raise exception 'invitation_already_pending' using errcode='23505';
 end if;
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),p_level,v_actor,now()+p_ttl)
 returning id into v_id;
 return query select v_id,v_token;
end $$;

create or replace function api.create_company_superadmin_invitation(
 p_tenant_id uuid,p_email text,p_ttl interval,p_limits jsonb,p_reason text
) returns table(invitation_id uuid,token text)
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_token text:=encode(extensions.gen_random_bytes(32),'hex');
        v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if v_actor is null or not private.is_platform_operator() or v_email is null
   or length(v_email)<3 or length(v_email)>254 or p_ttl is null or p_ttl<=interval '0'
   or p_ttl>interval '30 days' or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or not exists(select 1 from core.tenants t where t.id=p_tenant_id and t.status='active')
   or jsonb_typeof(p_limits)<>'array' or jsonb_array_length(p_limits)>100 then
   raise exception 'company_superadmin_invitation_not_allowed' using errcode='42501';
 end if;
 if exists(select 1 from jsonb_array_elements(p_limits) as e(value)
   where jsonb_typeof(e.value)<>'object' or exists(select 1 from jsonb_object_keys(e.value) as k(key)
     where k.key not in ('permission_key','can_use','can_delegate','reason')))
   or exists(select 1 from jsonb_to_recordset(p_limits) as x(
       permission_key text,can_use boolean,can_delegate boolean,reason text)
     where permission_key is null or can_use is null or can_delegate is null
       or can_delegate and not can_use or reason is null or length(btrim(reason)) not between 3 and 500
       or not (permission_key in ('role_assignment','direct_permission_decision','scope_management','permissions.specific_override')
          or exists(select 1 from iam.permission_catalog pc where pc.permission_key=x.permission_key and pc.module_key='hse')))
   then raise exception 'superadmin_invitation_limit_invalid' using errcode='22023'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-invitation:'||p_tenant_id::text||':'||v_email,0));
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.email=v_email and m.status='active') then
   raise exception 'active_membership_already_exists' using errcode='23505';
 end if;
 update iam.invitations set revoked_at=now(),revoked_by=v_actor,revoke_reason='Expired before reinvitation'
  where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null and expires_at<=now();
 if exists(select 1 from iam.invitations where tenant_id=p_tenant_id and email=v_email
    and accepted_at is null and revoked_at is null) then
   raise exception 'invitation_already_pending' using errcode='23505';
 end if;
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),'company_superadmin',v_actor,now()+p_ttl)
 returning id into v_id;
 insert into iam.superadmin_invitation_limits(tenant_id,invitation_id,permission_key,can_use,can_delegate,set_by,reason)
  select p_tenant_id,v_id,x.permission_key,x.can_use,x.can_delegate,v_actor,btrim(x.reason)
   from jsonb_to_recordset(p_limits) as x(permission_key text,can_use boolean,can_delegate boolean,reason text);
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,'tenant','iam.superadmin.invitation.created','iam.invitations',v_id,
    jsonb_build_object('email',v_email,'limit_count',jsonb_array_length(p_limits),'reason',btrim(p_reason)));
 return query select v_id,v_token;
end $$;

create or replace function api.set_default_permission_profile(
 p_tenant_id uuid,p_role_family text,p_profile_name text,p_permissions jsonb,
 p_target_mode text,p_target_membership_ids uuid[],p_reason text
) returns table(profile_id uuid,profile_version_id uuid,default_updated boolean)
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_actor_membership uuid; v_profile uuid; v_version uuid;
        v_version_no integer; v_ids uuid[]:=coalesce(p_target_membership_ids,array[]::uuid[]);
        v_default boolean:=p_target_mode in ('new_users_only','selected_existing_and_new_users');
begin
 select m.id into v_actor_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor
    and m.status='active' and t.status='active' and private.has_module_entitlement(p_tenant_id,'hse');
 if v_actor is null or v_actor_membership is null
   or not private.phase1_can_manage(p_tenant_id,'role_assignment',null,null,null) then
   raise exception 'permission_profile_management_not_delegated' using errcode='42501'; end if;
 if p_role_family is null or p_role_family not in ('admin','employee') or p_profile_name is null or length(btrim(p_profile_name)) not between 1 and 120
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_permissions is null or jsonb_typeof(p_permissions)<>'array' or jsonb_array_length(p_permissions)>100
   or p_target_mode not in ('new_users_only','selected_existing_users','selected_existing_and_new_users') then
   raise exception 'permission_profile_request_invalid' using errcode='22023';
 end if;
 if (p_target_mode='new_users_only' and cardinality(v_ids)<>0)
   or (p_target_mode<>'new_users_only' and (cardinality(v_ids)=0 or cardinality(v_ids)<>(select count(distinct x) from unnest(v_ids) x))) then
   raise exception 'explicit_profile_target_selection_required' using errcode='22023';
 end if;
 if p_target_mode='new_users_only' and not private.phase1_can_manage(p_tenant_id,'role_assignment',null,null,null) then
   raise exception 'default_profile_management_not_delegated' using errcode='42501';
 end if;
 if (select m.member_role from iam.memberships m where m.tenant_id=p_tenant_id and m.id=v_actor_membership)<>'company_superadmin'
   and p_role_family<>'employee' then
   raise exception 'delegated_default_profile_must_target_employee_family' using errcode='42501';
 end if;
 if exists(select 1 from jsonb_array_elements(p_permissions) as e(value)
   where jsonb_typeof(e.value)<>'object' or exists(select 1 from jsonb_object_keys(e.value) as k(key)
     where k.key not in ('permission_key','scope_kind','site_id','org_unit_id','can_read','can_write')))
   or exists(select 1 from jsonb_to_recordset(p_permissions) as x(
       permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean)
     where permission_key is null
       or scope_kind not in ('tenant','site','org_unit') or (not can_read and not can_write)
       or (scope_kind='site') is distinct from (site_id is not null)
       or (scope_kind='org_unit') is distinct from (org_unit_id is not null)) then
   raise exception 'permission_profile_permission_invalid' using errcode='22023';
 end if;
 if exists(select 1 from jsonb_to_recordset(p_permissions) as x(
      permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean)
    left join iam.permission_catalog pc on pc.permission_key=x.permission_key and pc.module_key='hse' and pc.enabled
    where pc.permission_key is null or (pc.feature_key is not null and
       not private.has_feature_entitlement(p_tenant_id,v_actor_membership,pc.feature_key))) then
   raise exception 'permission_not_enabled_for_company' using errcode='42501';
 end if;
 if p_target_mode<>'new_users_only' and exists(
   select 1 from unnest(v_ids) as selected_membership(membership_id)
    left join iam.memberships m on m.tenant_id=p_tenant_id and m.id=selected_membership.membership_id
   where m.id is null or m.status<>'active' or m.member_role='company_superadmin'
     or (case when m.member_role='employee' then 'employee' else 'admin' end)<>p_role_family
     or not private.phase1_can_manage(p_tenant_id,'role_assignment',m.id,null,null)) then
   raise exception 'profile_target_must_be_active_matching_family_member' using errcode='42501';
 end if;
 insert into iam.permission_profiles(tenant_id,role_family,profile_name,created_by)
  values(p_tenant_id,p_role_family,btrim(p_profile_name),v_actor)
  on conflict(tenant_id,role_family) do update set profile_name=excluded.profile_name
  returning id into v_profile;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-profile-version:'||p_tenant_id::text||':'||v_profile::text,0));
 select coalesce(max(pv.version_no),0)+1 into v_version_no from iam.permission_profile_versions pv
   where pv.tenant_id=p_tenant_id and pv.profile_id=v_profile;
 insert into iam.permission_profile_versions(tenant_id,profile_id,version_no,created_by)
  values(p_tenant_id,v_profile,v_version_no,v_actor) returning id into v_version;
 insert into iam.permission_profile_permissions(tenant_id,profile_version_id,permission_key,scope_kind,site_id,org_unit_id,can_read,can_write)
  select p_tenant_id,v_version,x.permission_key,x.scope_kind,x.site_id,x.org_unit_id,x.can_read,x.can_write
  from jsonb_to_recordset(p_permissions) as x(
    permission_key text,scope_kind text,site_id uuid,org_unit_id uuid,can_read boolean,can_write boolean);
 if v_default then
   insert into iam.permission_profile_defaults(tenant_id,role_family,profile_id,profile_version_id,updated_by)
    values(p_tenant_id,p_role_family,v_profile,v_version,v_actor)
    on conflict(tenant_id,role_family) do update set profile_id=excluded.profile_id,
      profile_version_id=excluded.profile_version_id,updated_by=excluded.updated_by,updated_at=now();
 end if;
 insert into iam.permission_profile_applications(tenant_id,profile_id,profile_version_id,target_mode,target_membership_ids,applied_by)
  values(p_tenant_id,v_profile,v_version,p_target_mode,v_ids,v_actor);
 if p_target_mode<>'new_users_only' then
   update iam.membership_permission_profiles set is_current=false
    where tenant_id=p_tenant_id and role_family=p_role_family and membership_id=any(v_ids) and is_current;
   insert into iam.membership_permission_profiles(tenant_id,membership_id,role_family,profile_id,profile_version_id,source,assigned_by,is_current)
    select p_tenant_id,m.id,p_role_family,v_profile,v_version,'explicit_application',v_actor,true
     from iam.memberships m where m.tenant_id=p_tenant_id and m.id=any(v_ids);
 end if;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_actor_membership,'tenant','iam.permission_profile.applied','iam.permission_profiles',v_profile,
    jsonb_build_object('role_family',p_role_family,'version_id',v_version,'target_mode',p_target_mode,'target_count',cardinality(v_ids),'reason',btrim(p_reason)));
 return query select v_profile,v_version,v_default;
end $$;

create or replace function api.set_member_permission_decision(
 p_tenant_id uuid,p_membership_id uuid,p_permission_key text,p_decision text,p_scope_kind text,
 p_site_id uuid,p_org_unit_id uuid,p_task_kind text,p_task_id uuid,p_can_read boolean,p_can_write boolean,
 p_ends_at timestamptz,p_exception_kind text,p_reason text
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_actor_membership uuid; v_id uuid; v_target iam.memberships%rowtype;
        v_feature text;
begin
 select m.id into v_actor_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active'
    and private.has_module_entitlement(p_tenant_id,'hse');
 select * into v_target from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id;
 if v_actor is null or v_actor_membership is null or v_target.id is null or v_target.status<>'active'
   or v_target.member_role='company_superadmin'
   or p_can_read is null or p_can_write is null
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_decision not in ('allow','deny') or p_scope_kind not in ('tenant','site','org_unit','assigned_task')
   or (p_scope_kind='site') is distinct from (p_site_id is not null)
   or (p_scope_kind='org_unit') is distinct from (p_org_unit_id is not null)
   or (p_scope_kind='assigned_task') is distinct from (p_task_id is not null and p_task_kind is not null)
   or (p_decision='deny' and (p_can_read or p_can_write or p_exception_kind is not null))
   or (p_decision='allow' and not (p_can_read or p_can_write))
   or (p_exception_kind is not null and (p_decision<>'allow' or p_exception_kind<>'specific_override')) then
   raise exception 'direct_permission_decision_invalid' using errcode='22023';
 end if;
 if not private.phase1_can_manage(p_tenant_id,'direct_permission_decision',p_membership_id,p_site_id,p_org_unit_id)
   or (p_exception_kind='specific_override' and not private.phase1_can_manage(p_tenant_id,'permissions.specific_override',p_membership_id,p_site_id,p_org_unit_id)) then
   raise exception 'direct_permission_decision_not_delegated' using errcode='42501';
 end if;
 select feature_key into v_feature from iam.permission_catalog where permission_key=p_permission_key and module_key='hse' and enabled;
 if not found then raise exception 'permission_key_not_in_enabled_catalog' using errcode='22023'; end if;
 if p_decision='allow' and v_feature is not null and not private.has_feature_entitlement(p_tenant_id,v_actor_membership,v_feature) then
   raise exception 'permission_feature_not_enabled' using errcode='42501';
 end if;
 if p_scope_kind='assigned_task' and not exists(select 1 from iam.task_assignments ta where ta.tenant_id=p_tenant_id
   and ta.membership_id=p_membership_id and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active) then
   raise exception 'task_scope_requires_active_assignment' using errcode='23503';
 end if;
 update iam.member_permission_decisions d set status='revoked',revoked_at=now(),revoked_by=v_actor,
   revoke_reason='Replaced by a new authorized decision'
 where d.tenant_id=p_tenant_id and d.membership_id=p_membership_id and d.permission_key=p_permission_key
   and d.scope_kind=p_scope_kind and d.site_id is not distinct from p_site_id
   and d.org_unit_id is not distinct from p_org_unit_id and d.task_kind is not distinct from p_task_kind
   and d.task_id is not distinct from p_task_id and d.status='active';
 insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,site_id,org_unit_id,
   task_kind,task_id,can_read,can_write,exception_kind,status,granted_by,ends_at,reason)
 values(p_tenant_id,p_membership_id,p_permission_key,p_decision,p_scope_kind,p_site_id,p_org_unit_id,p_task_kind,p_task_id,
   case when p_decision='deny' then false else p_can_read end,case when p_decision='deny' then false else p_can_write end,
   p_exception_kind,'active',v_actor,p_ends_at,btrim(p_reason)) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_actor_membership,p_scope_kind,'iam.permission_decision.set','iam.member_permission_decisions',v_id,
   jsonb_build_object('target_membership_id',p_membership_id,'permission_key',p_permission_key,'decision',p_decision,'reason',btrim(p_reason)));
 return v_id;
end $$;

create or replace function api.create_delegation(
 p_tenant_id uuid,p_delegate_membership_id uuid,p_level text,p_site_id uuid,p_org_unit_id uuid,
 p_allowed_capabilities text[],p_starts_at timestamptz,p_ends_at timestamptz,p_reason text
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_grantor uuid; v_parent uuid; v_id uuid; c text;
begin
 select m.id into v_grantor from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active' and t.status='active'
    and private.has_module_entitlement(p_tenant_id,'hse');
 if v_actor is null or v_grantor is null or p_allowed_capabilities is null or cardinality(p_allowed_capabilities)=0
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_starts_at is null or (p_ends_at is not null and p_ends_at<=p_starts_at) then
   raise exception 'delegation_request_invalid' using errcode='22023';
 end if;
 foreach c in array p_allowed_capabilities loop
   if not private.phase1_can_manage(p_tenant_id,c,p_delegate_membership_id,p_site_id,p_org_unit_id) then
     raise exception 'delegation_capability_not_authorized' using errcode='42501';
   end if;
 end loop;
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=v_grantor and m.member_role<>'company_superadmin') then
   select d.id into v_parent from iam.delegation_envelopes d where d.tenant_id=p_tenant_id
    and d.delegate_membership_id=v_grantor and d.status='active' and d.starts_at<=now()
    and (d.ends_at is null or now()<d.ends_at)
    and p_allowed_capabilities <@ d.allowed_capabilities
    and ((d.level='tenant') or (d.level='employees_default' and p_level='employees_default')
      or (d.level='site' and p_level='site' and d.site_id=p_site_id)
      or (d.level='org_unit' and p_level='org_unit' and d.org_unit_id=p_org_unit_id))
    and (d.ends_at is null or (p_ends_at is not null and p_ends_at<=d.ends_at))
    order by d.created_at desc limit 1;
   if v_parent is null then raise exception 'delegation_parent_envelope_required' using errcode='42501'; end if;
 end if;
 insert into iam.delegation_envelopes(tenant_id,grantor_membership_id,delegate_membership_id,level,site_id,org_unit_id,
   allowed_capabilities,starts_at,ends_at,parent_envelope_id,created_by)
 values(p_tenant_id,v_grantor,p_delegate_membership_id,p_level,p_site_id,p_org_unit_id,p_allowed_capabilities,
   p_starts_at,p_ends_at,v_parent,v_actor) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,v_grantor,p_level,'iam.delegation.created','iam.delegation_envelopes',v_id,
   jsonb_build_object('delegate_membership_id',p_delegate_membership_id,'capabilities',p_allowed_capabilities,'reason',btrim(p_reason)));
 return v_id;
end $$;

create or replace function api.revoke_delegation(p_tenant_id uuid,p_envelope_id uuid,p_reason text) returns integer
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_creator uuid; v_count integer;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
   raise exception 'delegation_revoke_invalid' using errcode='22023'; end if;
 select created_by into v_creator from iam.delegation_envelopes where tenant_id=p_tenant_id and id=p_envelope_id;
 if v_creator is null or (v_creator<>v_actor and not private.is_platform_operator()) then
   raise exception 'delegation_revoke_not_authorized' using errcode='42501'; end if;
 v_count:=private.revoke_delegation_tree(p_tenant_id,p_envelope_id,v_actor,btrim(p_reason),false);
 insert into iam.delegation_review_events(tenant_id,envelope_id,actor_user_id,action,previous_ends_at,reason)
  select p_tenant_id,p_envelope_id,v_actor,'revoke',d.ends_at,btrim(p_reason)
    from iam.delegation_envelopes d where d.tenant_id=p_tenant_id and d.id=p_envelope_id;
 return v_count;
end $$;

create or replace function api.review_delegation(p_tenant_id uuid,p_envelope_id uuid,p_action text,
 p_new_ends_at timestamptz,p_reason text) returns void
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_d iam.delegation_envelopes%rowtype; v_old_end timestamptz;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_action not in ('extend','confirm_expired') then raise exception 'delegation_review_invalid' using errcode='22023'; end if;
 select * into v_d from iam.delegation_envelopes where tenant_id=p_tenant_id and id=p_envelope_id for update;
 if not found or (v_d.created_by<>v_actor and not private.is_platform_operator())
   or v_d.status<>'active' then raise exception 'delegation_review_not_authorized' using errcode='42501'; end if;
 v_old_end:=v_d.ends_at;
 if p_action='extend' then
   if p_new_ends_at is null or p_new_ends_at<=now() or (v_old_end is not null and p_new_ends_at<=v_old_end)
     or (v_d.parent_envelope_id is not null and not exists(select 1 from iam.delegation_envelopes p
       where p.tenant_id=p_tenant_id and p.id=v_d.parent_envelope_id and p.status='active'
         and (p.ends_at is null or p_new_ends_at<=p.ends_at))) then
     raise exception 'delegation_extension_outside_parent_or_expired' using errcode='22023'; end if;
   update iam.delegation_envelopes set ends_at=p_new_ends_at where tenant_id=p_tenant_id and id=p_envelope_id;
 else
   if v_old_end is null or v_old_end>now() or p_new_ends_at is not null then
     raise exception 'delegation_not_expired' using errcode='22023'; end if;
 end if;
 insert into iam.delegation_review_events(tenant_id,envelope_id,actor_user_id,action,previous_ends_at,new_ends_at,reason)
  values(p_tenant_id,p_envelope_id,v_actor,p_action,v_old_end,case when p_action='extend' then p_new_ends_at end,btrim(p_reason));
end $$;

create or replace function api.set_superadmin_capability_limit(
 p_tenant_id uuid,p_membership_id uuid,p_capability_key text,p_can_use boolean,p_can_delegate boolean,p_reason text
) returns void language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid();
begin
 if v_actor is null or not private.is_platform_operator() or p_can_delegate and not p_can_use
   or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or not (p_capability_key in ('role_assignment','direct_permission_decision','scope_management','permissions.specific_override')
       or exists(select 1 from iam.permission_catalog pc where pc.permission_key=p_capability_key and pc.module_key='hse'))
   or not exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=p_membership_id
       and m.member_role='company_superadmin' and m.status='active') then
   raise exception 'superadmin_capability_limit_not_authorized' using errcode='42501';
 end if;
 insert into iam.superadmin_capability_limits(tenant_id,membership_id,capability_key,can_use,can_delegate,set_by,reason)
  values(p_tenant_id,p_membership_id,p_capability_key,p_can_use,p_can_delegate,v_actor,btrim(p_reason))
  on conflict(tenant_id,membership_id,capability_key) do update set can_use=excluded.can_use,
   can_delegate=excluded.can_delegate,set_by=excluded.set_by,reason=excluded.reason,updated_at=now();
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(p_tenant_id,v_actor,'tenant','iam.superadmin_capability_limit.set','iam.superadmin_capability_limits',p_membership_id,
    jsonb_build_object('capability_key',p_capability_key,'can_use',p_can_use,'can_delegate',p_can_delegate,'reason',btrim(p_reason)));
end $$;

-- A delegated role change must go through this API so each assigned scope is
-- checked against the actor's tenant/site/org-unit envelope.
create or replace function api.assign_membership_role(
 p_tenant_id uuid,p_membership_id uuid,p_role_id uuid,p_role_version_id uuid,
 p_site_ids uuid[],p_org_unit_ids uuid[],p_starts_at timestamptz,p_ends_at timestamptz,p_reason text
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_role iam.roles%rowtype; v_target iam.memberships%rowtype;
        v_id uuid; v_site uuid; v_org uuid; v_has_tenant_scope boolean; v_expected_family text;
begin
 if v_actor is null or p_reason is null or length(btrim(p_reason)) not between 3 and 500
   or p_starts_at is null or p_starts_at<now() or (p_ends_at is not null and p_ends_at<=p_starts_at)
   or cardinality(coalesce(p_site_ids,'{}'::uuid[]))<>(select count(distinct x) from unnest(coalesce(p_site_ids,'{}'::uuid[])) x)
   or cardinality(coalesce(p_org_unit_ids,'{}'::uuid[]))<>(select count(distinct x) from unnest(coalesce(p_org_unit_ids,'{}'::uuid[])) x) then
   raise exception 'membership_role_assignment_invalid' using errcode='22023';
 end if;
 select * into v_target from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id for key share;
 select * into v_role from iam.roles where tenant_id=p_tenant_id and id=p_role_id and active for key share;
 if v_target.id is null or v_target.status<>'active' or v_target.member_role='company_superadmin'
   or v_role.id is null or v_role.role_family is null then
   raise exception 'membership_role_target_or_role_invalid' using errcode='23503';
 end if;
 if not exists(select 1 from iam.role_versions rv where rv.tenant_id=p_tenant_id and rv.id=p_role_version_id
      and rv.role_id=p_role_id and rv.role_family=v_role.role_family and rv.status='published') then
   raise exception 'published_role_version_required' using errcode='23514';
 end if;
 v_expected_family:=case when v_target.member_role='employee' then 'employee' else 'admin' end;
 if v_role.role_family<>v_expected_family then
   raise exception 'role_family_target_mismatch' using errcode='23514';
 end if;
 select exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id and rp.scope_kind='tenant')
  into v_has_tenant_scope;
 if exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id and rp.scope_kind='assigned_task') then
   raise exception 'assigned_task_role_permissions_require_direct_task_decisions' using errcode='23514';
 end if;
 if v_has_tenant_scope and not private.phase1_can_manage(p_tenant_id,'role_assignment',v_target.id,null,null) then
   raise exception 'tenant_role_assignment_not_delegated' using errcode='42501';
 end if;
 if not exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id) then
   raise exception 'empty_role_version_not_assignable' using errcode='23514';
 end if;
 foreach v_site in array coalesce(p_site_ids,'{}'::uuid[]) loop
   if not exists(select 1 from core.sites s where s.tenant_id=p_tenant_id and s.id=v_site and s.active)
     or not exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id and rp.scope_kind='site')
     or not private.phase1_can_manage(p_tenant_id,'role_assignment',v_target.id,v_site,null) then
     raise exception 'site_role_assignment_scope_not_delegated' using errcode='42501';
   end if;
 end loop;
 foreach v_org in array coalesce(p_org_unit_ids,'{}'::uuid[]) loop
   if not exists(select 1 from core.org_units o where o.tenant_id=p_tenant_id and o.id=v_org)
     or not exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id and rp.scope_kind='org_unit')
     or not private.phase1_can_manage(p_tenant_id,'role_assignment',v_target.id,null,v_org) then
     raise exception 'org_role_assignment_scope_not_delegated' using errcode='42501';
   end if;
 end loop;
 if exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id and rp.scope_kind='site')
    and cardinality(coalesce(p_site_ids,'{}'::uuid[]))=0
    and exists(select 1 from iam.role_version_permissions rp where rp.role_version_id=p_role_version_id and rp.scope_kind='tenant') then
   raise exception 'mixed_role_scopes_require_explicit_site_selection' using errcode='22023';
 end if;
 insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,starts_at,ends_at,granted_by)
 values(p_tenant_id,p_membership_id,p_role_id,p_role_version_id,p_starts_at,p_ends_at,v_actor) returning id into v_id;
 insert into iam.membership_role_sites(tenant_id,membership_role_id,site_id,granted_by,granted_at,ends_at)
  select p_tenant_id,v_id,x,v_actor,p_starts_at,p_ends_at from unnest(coalesce(p_site_ids,'{}'::uuid[])) x;
 insert into iam.membership_role_org_units(tenant_id,membership_role_id,org_unit_id,granted_by,granted_at,ends_at)
  select p_tenant_id,v_id,x,v_actor,p_starts_at,p_ends_at from unnest(coalesce(p_org_unit_ids,'{}'::uuid[])) x;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
  select p_tenant_id,v_actor,m.id,'tenant','iam.membership_role.assigned','iam.membership_roles',v_id,
   jsonb_build_object('target_membership_id',p_membership_id,'role_id',p_role_id,'role_version_id',p_role_version_id,
    'site_count',cardinality(coalesce(p_site_ids,'{}'::uuid[])),'org_unit_count',cardinality(coalesce(p_org_unit_ids,'{}'::uuid[])),
    'reason',btrim(p_reason)) from iam.memberships m where m.tenant_id=p_tenant_id and m.user_id=v_actor and m.status='active';
 return v_id;
end $$;

-- New permission tables are readable only to active tenant members (or the
-- involved actor); all writes use audited SECURITY DEFINER APIs/triggers.
alter table iam.permission_profile_defaults enable row level security;
alter table iam.permission_profile_defaults force row level security;
alter table iam.delegation_review_events enable row level security;
alter table iam.delegation_review_events force row level security;
alter table iam.permission_profiles enable row level security;
alter table iam.permission_profiles force row level security;
alter table iam.permission_profile_versions enable row level security;
alter table iam.permission_profile_versions force row level security;
alter table iam.permission_profile_permissions enable row level security;
alter table iam.permission_profile_permissions force row level security;
alter table iam.membership_permission_profiles enable row level security;
alter table iam.membership_permission_profiles force row level security;
alter table iam.permission_profile_applications enable row level security;
alter table iam.permission_profile_applications force row level security;
alter table iam.member_permission_decisions enable row level security;
alter table iam.member_permission_decisions force row level security;
alter table iam.delegation_envelopes enable row level security;
alter table iam.delegation_envelopes force row level security;
alter table iam.superadmin_invitation_limits enable row level security;
alter table iam.superadmin_invitation_limits force row level security;
alter table iam.superadmin_capability_limits enable row level security;
alter table iam.superadmin_capability_limits force row level security;

revoke all on iam.permission_profile_defaults,iam.permission_profiles,iam.permission_profile_versions,
 iam.permission_profile_permissions,iam.membership_permission_profiles,iam.permission_profile_applications,
 iam.member_permission_decisions,iam.delegation_envelopes,iam.delegation_review_events,
 iam.superadmin_invitation_limits,iam.superadmin_capability_limits from public,anon,authenticated,service_role;
grant select on iam.permission_profile_defaults,iam.permission_profiles,iam.permission_profile_versions,
 iam.permission_profile_permissions,iam.membership_permission_profiles,iam.permission_profile_applications,
 iam.member_permission_decisions,iam.delegation_envelopes,iam.delegation_review_events,
 iam.superadmin_invitation_limits,iam.superadmin_capability_limits to authenticated;

drop policy if exists permission_profile_defaults_read on iam.permission_profile_defaults;
create policy permission_profile_defaults_read on iam.permission_profile_defaults for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists permission_profiles_read on iam.permission_profiles;
create policy permission_profiles_read on iam.permission_profiles for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists permission_profile_versions_read on iam.permission_profile_versions;
create policy permission_profile_versions_read on iam.permission_profile_versions for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists permission_profile_permissions_read on iam.permission_profile_permissions;
create policy permission_profile_permissions_read on iam.permission_profile_permissions for select to authenticated
 using(private.phase1_membership(tenant_id) is not null);
drop policy if exists membership_permission_profiles_read on iam.membership_permission_profiles;
create policy membership_permission_profiles_read on iam.membership_permission_profiles for select to authenticated
 using(membership_id=private.phase1_membership(tenant_id) or exists(select 1 from iam.memberships m
   where m.tenant_id=iam.membership_permission_profiles.tenant_id and m.id=private.phase1_membership(tenant_id)
     and m.member_role='company_superadmin'));
drop policy if exists permission_profile_applications_read on iam.permission_profile_applications;
create policy permission_profile_applications_read on iam.permission_profile_applications for select to authenticated
 using(applied_by=(select auth.uid()) or exists(select 1 from iam.memberships m where m.tenant_id=iam.permission_profile_applications.tenant_id
   and m.id=private.phase1_membership(tenant_id) and m.member_role='company_superadmin'));
drop policy if exists member_permission_decisions_read on iam.member_permission_decisions;
create policy member_permission_decisions_read on iam.member_permission_decisions for select to authenticated
 using(membership_id=private.phase1_membership(tenant_id) or exists(select 1 from iam.memberships m where m.tenant_id=iam.member_permission_decisions.tenant_id
   and m.id=private.phase1_membership(tenant_id) and m.member_role='company_superadmin'));
drop policy if exists delegation_envelopes_read on iam.delegation_envelopes;
create policy delegation_envelopes_read on iam.delegation_envelopes for select to authenticated
 using(grantor_membership_id=private.phase1_membership(tenant_id) or delegate_membership_id=private.phase1_membership(tenant_id)
   or exists(select 1 from iam.memberships m where m.tenant_id=iam.delegation_envelopes.tenant_id
     and m.id=private.phase1_membership(tenant_id) and m.member_role='company_superadmin'));
drop policy if exists delegation_review_events_read on iam.delegation_review_events;
create policy delegation_review_events_read on iam.delegation_review_events for select to authenticated
 using(exists(select 1 from iam.delegation_envelopes d where d.tenant_id=iam.delegation_review_events.tenant_id
   and d.id=iam.delegation_review_events.envelope_id and (d.grantor_membership_id=private.phase1_membership(d.tenant_id)
     or d.delegate_membership_id=private.phase1_membership(d.tenant_id))));
drop policy if exists superadmin_invitation_limits_read on iam.superadmin_invitation_limits;
create policy superadmin_invitation_limits_read on iam.superadmin_invitation_limits for select to authenticated
 using(private.is_platform_operator() or membership_id=private.phase1_membership(tenant_id));
drop policy if exists superadmin_capability_limits_read on iam.superadmin_capability_limits;
create policy superadmin_capability_limits_read on iam.superadmin_capability_limits for select to authenticated
 using(private.is_platform_operator() or membership_id=private.phase1_membership(tenant_id));

revoke all on function private.people_delegation_allows(uuid,uuid,text,uuid,uuid,uuid),
 private.phase1_can_manage(uuid,text,uuid,uuid,uuid),private.guard_delegation_envelope(),
 private.revoke_delegation_tree(uuid,uuid,uuid,text,boolean),private.revoke_delegations_on_membership_change(),
 private.revoke_delegations_on_tenant_suspend(),private.revoke_delegations_on_engagement_end(),
 private.validate_membership_permission_profile(),private.guard_permission_profile_immutability(),
 private.guard_delegation_review_immutable(),private.apply_invitation_phase1_defaults() from public,anon,authenticated,service_role;
revoke all on function api.set_default_permission_profile(uuid,text,text,jsonb,text,uuid[],text),
 api.set_member_permission_decision(uuid,uuid,text,text,text,uuid,uuid,text,uuid,boolean,boolean,timestamptz,text,text),
 api.create_delegation(uuid,uuid,text,uuid,uuid,text[],timestamptz,timestamptz,text),
 api.revoke_delegation(uuid,uuid,text),api.review_delegation(uuid,uuid,text,timestamptz,text),
 api.set_superadmin_capability_limit(uuid,uuid,text,boolean,boolean,text),
 api.create_company_invitation(uuid,text,text,interval),
 api.create_company_superadmin_invitation(uuid,text,interval,jsonb,text),
 api.assign_membership_role(uuid,uuid,uuid,uuid,uuid[],uuid[],timestamptz,timestamptz,text)
 from public,anon,authenticated,service_role;
grant execute on function api.set_default_permission_profile(uuid,text,text,jsonb,text,uuid[],text),
 api.set_member_permission_decision(uuid,uuid,text,text,text,uuid,uuid,text,uuid,boolean,boolean,timestamptz,text,text),
 api.create_delegation(uuid,uuid,text,uuid,uuid,text[],timestamptz,timestamptz,text),
 api.revoke_delegation(uuid,uuid,text),api.review_delegation(uuid,uuid,text,timestamptz,text),
 api.set_superadmin_capability_limit(uuid,uuid,text,boolean,boolean,text),
 api.create_company_invitation(uuid,text,text,interval),
 api.create_company_superadmin_invitation(uuid,text,interval,jsonb,text),
 api.assign_membership_role(uuid,uuid,uuid,uuid,uuid[],uuid[],timestamptz,timestamptz,text)
 to authenticated;
revoke all on function api.set_default_permission_profile(uuid,text,text,jsonb,text,uuid[],text),
 api.set_member_permission_decision(uuid,uuid,text,text,text,uuid,uuid,text,uuid,boolean,boolean,timestamptz,text,text),
 api.create_delegation(uuid,uuid,text,uuid,uuid,text[],timestamptz,timestamptz,text),
 api.revoke_delegation(uuid,uuid,text),api.review_delegation(uuid,uuid,text,timestamptz,text),
 api.set_superadmin_capability_limit(uuid,uuid,text,boolean,boolean,text),
 api.create_company_invitation(uuid,text,text,interval),
 api.create_company_superadmin_invitation(uuid,text,interval,jsonb,text),
 api.assign_membership_role(uuid,uuid,uuid,uuid,uuid[],uuid[],timestamptz,timestamptz,text)
 from service_role;

commit;
