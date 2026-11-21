-- SENTRIQ Phase 1: tenant-owned People, workforce engagements, and bounded IAM.
-- Forward-only. This migration intentionally leaves legacy HSE policies in place;
-- the new People boundary does not call their platform/superadmin bypass helpers.
begin;

-- The canonical catalog owns all technical keys. These seven keys are the
-- approved Phase 1 People capabilities; they do not create a second catalog.
insert into iam.permission_catalog(permission_key,module_key,label,description,enabled) values
 ('view_all','hse','View People and workforce records','Read tenant People, contractor, and engagement records',true),
 ('create_edit','hse','Create and edit People records','Create and update operational People and engagement records',true),
 ('export','hse','Export People records','Export only records visible under effective scope',true),
 ('contractors','hse','Manage contractor organizations','Create and update tenant contractor organizations',true),
 ('engagements','hse','Manage person engagements','Create, update, and end operational engagements',true),
 ('scope_assign','hse','Manage operational scopes','Assign site and organizational access within delegation limits',true),
 ('membership_link','hse','Link People to memberships','Link an operational person to a same-tenant login membership',true)
on conflict(permission_key) do update set module_key=excluded.module_key,label=excluded.label,
 description=excluded.description,enabled=true;

alter table iam.permission_catalog add column if not exists feature_key text
 references core.features(feature_key) on delete restrict;
update iam.permission_catalog set feature_key='hse.copilot'
 where permission_key='hse.copilot.use' and feature_key is null
   and exists(select 1 from core.features where feature_key='hse.copilot');

alter table iam.roles add column if not exists role_family text;
alter table iam.roles add constraint roles_tenant_family_check
 check(tenant_id is null or role_family in ('admin','employee')) not valid;
-- Composite references are used throughout the Phase 1 schema. The legacy
-- invitation table only declared id globally unique; expose the tenant pair.
create unique index if not exists invitations_tenant_id_unique on iam.invitations(tenant_id,id);
do $$
declare v_roles text;
begin
 select string_agg(r.tenant_id::text||'/'||r.role_key,', ' order by r.tenant_id,r.role_key)
 into v_roles from iam.roles r where r.tenant_id is not null and exists(
   select 1 from iam.membership_roles mr where mr.tenant_id=r.tenant_id and mr.role_id=r.id and mr.revoked_at is null)
   and r.role_family is null;
 if v_roles is not null then
   raise exception 'assign an Admin or Employee family to tenant roles before Phase 1 migration: %',v_roles using errcode='23514';
 end if;
end $$;

-- A role version is an immutable, published snapshot. Membership role rows pin
-- a version, so edits can coexist and be selectively rolled forward/back.
create table iam.role_versions (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references core.tenants(id) on delete restrict,
 role_id uuid not null references iam.roles(id) on delete restrict,
 version_no integer not null check(version_no>0),
 role_family text not null check(role_family in ('admin','employee')),
 status text not null default 'published' check(status in ('draft','published','retired')),
 created_by uuid not null references auth.users(id) on delete restrict,
 created_at timestamptz not null default now(), published_at timestamptz,
 unique(tenant_id,id), unique(tenant_id,role_id,version_no), unique(id,role_id),
 check((status='published')=(published_at is not null))
);
create table iam.role_version_permissions (
 role_version_id uuid not null references iam.role_versions(id) on delete restrict,
 permission_key text not null references iam.permission_catalog(permission_key) on delete restrict,
 scope_kind text not null check(scope_kind in ('tenant','site','org_unit','assigned_task')),
 can_read boolean not null default false, can_write boolean not null default false,
 primary key(role_version_id,permission_key,scope_kind), check(can_read or can_write)
);
alter table iam.membership_roles add column if not exists role_version_id uuid;
do $$
declare v record; v_version uuid;
begin
 for v in select distinct mr.tenant_id,mr.role_id,r.role_key,r.role_family
   from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
   where r.tenant_id=mr.tenant_id and r.tenant_id is not null
 loop
   update iam.roles set role_family=coalesce(role_family,'employee') where id=v.role_id;
   insert into iam.role_versions(tenant_id,role_id,version_no,role_family,status,created_by,published_at)
   values(v.tenant_id,v.role_id,1,coalesce(v.role_family,'employee'),'published',
     coalesce((select user_id from iam.memberships where tenant_id=v.tenant_id and id=(select membership_id from iam.membership_roles where tenant_id=v.tenant_id and role_id=v.role_id limit 1)),
       (select user_id from iam.memberships where tenant_id=v.tenant_id limit 1)),now())
   on conflict(tenant_id,role_id,version_no) do nothing returning id into v_version;
   if v_version is null then select id into v_version from iam.role_versions where tenant_id=v.tenant_id and role_id=v.role_id and version_no=1; end if;
   insert into iam.role_version_permissions(role_version_id,permission_key,scope_kind,can_read,can_write)
   select v_version,rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write
   from iam.role_permissions rp where rp.role_id=v.role_id and rp.active
   on conflict do nothing;
   update iam.membership_roles set role_version_id=v_version
    where tenant_id=v.tenant_id and role_id=v.role_id and role_version_id is null;
 end loop;
end $$;
alter table iam.membership_roles add constraint membership_roles_version_fk
 foreign key(tenant_id,role_version_id) references iam.role_versions(tenant_id,id) on delete restrict;

-- Tenant-scoped operational person profiles; login identity remains in IAM.
create table hse.people (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
 display_name text not null check(length(btrim(display_name)) between 1 and 200),
 person_kind text not null check(person_kind in ('employee','contractor','visitor','temporary','other')),
 status text not null default 'active' check(status in ('active','inactive')),
 worker_number text check(worker_number is null or length(btrim(worker_number)) between 1 and 80),
 membership_id uuid, created_by uuid not null references auth.users(id) on delete restrict,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 unique(tenant_id,id),
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict
);
create unique index people_membership_unique on hse.people(tenant_id,membership_id) where membership_id is not null;
create unique index people_worker_number_unique on hse.people(tenant_id,worker_number) where worker_number is not null;
create index people_tenant_name_idx on hse.people(tenant_id,lower(display_name));

create table hse.contractor_organizations (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
 name text not null check(length(btrim(name)) between 1 and 200),
 external_reference text check(external_reference is null or length(btrim(external_reference)) between 1 and 100),
 status text not null default 'active' check(status in ('active','inactive')),
 created_by uuid not null references auth.users(id) on delete restrict,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 unique(tenant_id,id)
);
create unique index contractor_org_external_reference_unique on hse.contractor_organizations(tenant_id,external_reference)
 where external_reference is not null;
create index contractor_org_tenant_name_idx on hse.contractor_organizations(tenant_id,lower(name));

create table hse.person_engagements (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
 person_id uuid not null, engagement_type text not null check(engagement_type in ('employee','contractor','visitor','temporary','other')),
 contractor_organization_id uuid, site_id uuid, org_unit_id uuid,
 starts_at timestamptz not null default now(), ends_at timestamptz,
 status text not null default 'active' check(status in ('active','ended','cancelled')),
 job_title_snapshot text check(job_title_snapshot is null or length(job_title_snapshot)<=200),
 external_worker_reference text check(external_worker_reference is null or length(external_worker_reference)<=100),
 created_by uuid not null references auth.users(id) on delete restrict,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 unique(tenant_id,id),
 foreign key(tenant_id,person_id) references hse.people(tenant_id,id) on delete restrict,
 foreign key(tenant_id,contractor_organization_id) references hse.contractor_organizations(tenant_id,id) on delete restrict,
 foreign key(tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict,
 check(ends_at is null or starts_at<ends_at),
 check((status='active')=(ends_at is null)),
 check((engagement_type='contractor')=(contractor_organization_id is not null))
);
create index person_engagement_person_start_idx on hse.person_engagements(tenant_id,person_id,starts_at desc);
create index person_engagement_site_active_idx on hse.person_engagements(tenant_id,site_id,org_unit_id) where status='active';
create index person_engagement_contractor_idx on hse.person_engagements(tenant_id,contractor_organization_id) where contractor_organization_id is not null;

create table hse.person_engagement_events (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, person_id uuid not null, engagement_id uuid not null,
 event_type text not null check(event_type in ('created','updated','started','ended','cancelled','corrected','site_changed','org_unit_changed','contractor_organization_changed','engagement_type_changed','status_changed')),
 actor_user_id uuid not null references auth.users(id) on delete restrict,
 actor_membership_id uuid, occurred_at timestamptz not null default now(), reason text,
 before_values jsonb not null default '{}'::jsonb check(jsonb_typeof(before_values)='object'),
 after_values jsonb not null default '{}'::jsonb check(jsonb_typeof(after_values)='object'),
 supersedes_event_id uuid, request_id text,
 unique(tenant_id,id),
 foreign key(tenant_id,person_id) references hse.people(tenant_id,id) on delete restrict,
 foreign key(tenant_id,engagement_id) references hse.person_engagements(tenant_id,id) on delete restrict,
 foreign key(tenant_id,actor_membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 foreign key(tenant_id,supersedes_event_id) references hse.person_engagement_events(tenant_id,id) on delete restrict,
 check(supersedes_event_id is null or supersedes_event_id<>id)
);
create index person_engagement_events_parent_idx on hse.person_engagement_events(tenant_id,person_id,engagement_id,occurred_at desc);

-- Role-based default profiles are immutable versions. Updating a default has
-- an explicit target mode; direct decisions and their denies are independent.
create table iam.permission_profiles (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
 role_family text not null check(role_family in ('admin','employee')),
 profile_name text not null check(length(btrim(profile_name)) between 1 and 120),
 current_version integer not null default 1 check(current_version>0), active boolean not null default true,
 created_by uuid not null references auth.users(id) on delete restrict, created_at timestamptz not null default now(),
 unique(tenant_id,id), unique(tenant_id,role_family)
);
create table iam.permission_profile_versions (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, profile_id uuid not null,
 version_no integer not null check(version_no>0), created_by uuid not null references auth.users(id) on delete restrict,
 created_at timestamptz not null default now(), unique(tenant_id,id), unique(tenant_id,profile_id,version_no),
 foreign key(tenant_id,profile_id) references iam.permission_profiles(tenant_id,id) on delete restrict
);
create table iam.permission_profile_permissions (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, profile_version_id uuid not null, permission_key text not null references iam.permission_catalog(permission_key) on delete restrict,
 scope_kind text not null check(scope_kind in ('tenant','site','org_unit','assigned_task')),
 site_id uuid, org_unit_id uuid, can_read boolean not null default false, can_write boolean not null default false,
 foreign key(tenant_id,profile_version_id) references iam.permission_profile_versions(tenant_id,id) on delete restrict,
 foreign key(tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict,
 check(can_read or can_write),
 check((scope_kind='site')=(site_id is not null)),
 check((scope_kind='org_unit')=(org_unit_id is not null))
);
create unique index permission_profile_permission_key_unique on iam.permission_profile_permissions
 (tenant_id,profile_version_id,permission_key,scope_kind,
  coalesce(site_id,'00000000-0000-0000-0000-000000000000'::uuid),
  coalesce(org_unit_id,'00000000-0000-0000-0000-000000000000'::uuid));
create table iam.membership_permission_profiles (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, membership_id uuid not null,
 role_family text not null check(role_family in ('admin','employee')),
 profile_id uuid not null, profile_version_id uuid not null,
 source text not null check(source in ('invitation_default','explicit_application','adopted')),
 assigned_by uuid references auth.users(id) on delete restrict, assigned_at timestamptz not null default now(),
 is_current boolean not null default true,
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 foreign key(tenant_id,profile_id) references iam.permission_profiles(tenant_id,id) on delete restrict,
 foreign key(tenant_id,profile_version_id) references iam.permission_profile_versions(tenant_id,id) on delete restrict
);
create unique index one_current_permission_profile_per_family on iam.membership_permission_profiles(tenant_id,membership_id,role_family) where is_current;
create table iam.permission_profile_applications (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, profile_id uuid not null,
 profile_version_id uuid not null, target_mode text not null check(target_mode in ('new_users_only','selected_existing_users','selected_existing_and_new_users')),
 target_membership_ids uuid[] not null default '{}', applied_by uuid not null references auth.users(id) on delete restrict,
 applied_at timestamptz not null default now(),
 foreign key(tenant_id,profile_id) references iam.permission_profiles(tenant_id,id) on delete restrict,
 foreign key(tenant_id,profile_version_id) references iam.permission_profile_versions(tenant_id,id) on delete restrict,
 check((target_mode='new_users_only')=(cardinality(target_membership_ids)=0))
);

-- Direct permission decisions are separate from reusable role/profile allows.
-- Deny takes precedence unless a separately-authorized specific override exists.
create table iam.member_permission_decisions (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, membership_id uuid not null,
 permission_key text not null references iam.permission_catalog(permission_key) on delete restrict,
 decision text not null check(decision in ('allow','deny')),
 scope_kind text not null check(scope_kind in ('tenant','site','org_unit','assigned_task')),
 site_id uuid, org_unit_id uuid, task_kind text, task_id uuid,
 can_read boolean not null default false, can_write boolean not null default false,
 exception_kind text check(exception_kind is null or exception_kind='specific_override'),
 status text not null default 'active' check(status in ('active','suspended','revoked')),
 granted_by uuid not null references auth.users(id) on delete restrict,
 starts_at timestamptz not null default now(), ends_at timestamptz, reason text not null check(length(btrim(reason)) between 3 and 500),
 revoked_at timestamptz, revoked_by uuid references auth.users(id) on delete restrict, revoke_reason text,
 created_at timestamptz not null default now(),
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 foreign key(tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict,
 check(ends_at is null or starts_at<ends_at),
 check((decision='allow' and (can_read or can_write)) or (decision='deny' and not can_read and not can_write)),
 check((scope_kind='site')=(site_id is not null)),
 check((scope_kind='org_unit')=(org_unit_id is not null)),
 check((scope_kind='assigned_task')=(task_id is not null and task_kind is not null)),
 check(exception_kind is null or (decision='allow' and scope_kind<>'tenant')),
 check((status='revoked')=(revoked_at is not null)),
 check((revoked_at is null and revoked_by is null and revoke_reason is null) or (revoked_at is not null and revoked_by is not null and length(btrim(revoke_reason))>=3))
);
create index member_permission_decision_lookup_idx on iam.member_permission_decisions(tenant_id,membership_id,permission_key,status,starts_at,ends_at);
do $$
declare v_bad text;
begin
 select string_agg(mp.id::text,', ' order by mp.id) into v_bad
 from iam.member_permissions mp where mp.active and mp.scope_kind='assigned_task'
   and (select count(*) from iam.task_assignments ta where ta.tenant_id=mp.tenant_id
      and ta.membership_id=mp.membership_id and ta.task_id=mp.task_id)<>1;
 if v_bad is not null then
   raise exception 'unmatched or ambiguous legacy task permissions require owner review: %',v_bad using errcode='23514';
 end if;
end $$;
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,
 site_id,org_unit_id,task_kind,task_id,can_read,can_write,granted_by,starts_at,reason)
select mp.tenant_id,mp.membership_id,mp.permission_key,'allow',mp.scope_kind,mp.site_id,mp.org_unit_id,
 case when mp.scope_kind='assigned_task' then (select ta.task_kind from iam.task_assignments ta
   where ta.tenant_id=mp.tenant_id and ta.membership_id=mp.membership_id and ta.task_id=mp.task_id limit 1) end,
 mp.task_id,mp.can_read,mp.can_write,mp.granted_by,mp.created_at,'Migrated from legacy direct allow'
from iam.member_permissions mp where mp.active
on conflict do nothing;

-- Platform-controlled restrictions captured at Superadmin invitation time.
-- Missing rows mean the default capability is allowed; a deny cannot be widened
-- by tenant administration. The feature catalog/entitlement remains a hard gate.
create table iam.superadmin_invitation_limits (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null, invitation_id uuid,
 membership_id uuid, permission_key text not null references iam.permission_catalog(permission_key) on delete restrict,
 can_use boolean not null default true, can_delegate boolean not null default true,
 set_by uuid not null references auth.users(id) on delete restrict,
 reason text not null check(length(btrim(reason)) between 3 and 500), created_at timestamptz not null default now(),
 foreign key(tenant_id,invitation_id) references iam.invitations(tenant_id,id) on delete restrict,
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 check((invitation_id is not null)::integer+(membership_id is not null)::integer=1),
 unique(tenant_id,invitation_id,permission_key), unique(tenant_id,membership_id,permission_key)
);

-- Delegation is an explicit capability envelope, separate from feature use.
create table iam.delegation_envelopes (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
 grantor_membership_id uuid not null, delegate_membership_id uuid not null,
 level text not null check(level in ('tenant','site','org_unit','employees_default')),
 site_id uuid, org_unit_id uuid, allowed_capabilities text[] not null,
 starts_at timestamptz not null default now(), ends_at timestamptz,
 status text not null default 'active' check(status in ('active','suspended','revoked')),
 created_by uuid not null references auth.users(id) on delete restrict, created_at timestamptz not null default now(),
 revoked_by uuid references auth.users(id) on delete restrict, revoked_at timestamptz, revoke_reason text,
 foreign key(tenant_id,grantor_membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 foreign key(tenant_id,delegate_membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 foreign key(tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict,
 unique(tenant_id,id), check(grantor_membership_id<>delegate_membership_id),
 check(ends_at is null or starts_at<ends_at),
 check((level='site')=(site_id is not null)), check((level='org_unit')=(org_unit_id is not null)),
 check(cardinality(allowed_capabilities)>0),
 check((status='revoked')=(revoked_at is not null)),
 check((revoked_at is null and revoked_by is null and revoke_reason is null) or (revoked_at is not null and revoked_by is not null and length(btrim(revoke_reason))>=3))
);
create index delegation_active_delegate_idx on iam.delegation_envelopes(tenant_id,delegate_membership_id,starts_at,ends_at) where status='active';

-- Superadmin target authority limits are platform-only. Personal exceptions
-- such as Copilot are non-delegable unless a Platform Operator records it.
create table iam.superadmin_capability_limits (
 tenant_id uuid not null, membership_id uuid not null, capability_key text not null,
 can_use boolean not null default true, can_delegate boolean not null default true,
 set_by uuid not null references auth.users(id) on delete restrict, reason text not null,
 updated_at timestamptz not null default now(),
 primary key(tenant_id,membership_id,capability_key),
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete restrict,
 check(length(btrim(reason)) between 3 and 500)
);

-- The legacy org tree is tenant-bound but currently permits cycles. Serialize
-- parent changes per tenant, then reject self/ancestor loops before writing.
create or replace function private.guard_org_unit_cycle() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_cycle boolean;
begin
 if new.parent_id is null then return new; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-org-tree:'||new.tenant_id::text,0));
 if new.parent_id=new.id then raise exception 'org_unit_cycle' using errcode='23514'; end if;
 with recursive ancestors(id,parent_id) as (
   select id,parent_id from core.org_units where tenant_id=new.tenant_id and id=new.parent_id
   union all
   select o.id,o.parent_id from core.org_units o join ancestors a on o.tenant_id=new.tenant_id and o.id=a.parent_id
 ) select exists(select 1 from ancestors where id=new.id) into v_cycle;
 if v_cycle then raise exception 'org_unit_cycle' using errcode='23514'; end if;
 return new;
end $$;
drop trigger if exists org_unit_cycle_guard on core.org_units;
create trigger org_unit_cycle_guard before insert or update of parent_id on core.org_units
 for each row execute function private.guard_org_unit_cycle();

-- Lock the parent Site before checking D-20 so Site reassignment and engagement
-- writes serialize. Site-less engagements may independently reference an org.
create or replace function private.guard_person_engagement_site_org() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_site_org uuid;
begin
 if new.site_id is null then return new; end if;
 select s.org_unit_id into v_site_org from core.sites s
  where s.tenant_id=new.tenant_id and s.id=new.site_id for update;
 if not found then raise exception 'engagement_site_not_found' using errcode='23503'; end if;
 if new.org_unit_id is distinct from v_site_org then
   raise exception 'engagement_site_org_mismatch' using errcode='23514';
 end if;
 return new;
end $$;
create trigger person_engagement_site_org_guard before insert or update of tenant_id,site_id,org_unit_id
 on hse.person_engagements for each row execute function private.guard_person_engagement_site_org();

create or replace function private.guard_site_engagement_org_reassignment() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.org_unit_id is not distinct from old.org_unit_id then return new; end if;
 if exists(select 1 from hse.person_engagements e where e.tenant_id=old.tenant_id and e.site_id=old.id
      and e.status='active' and e.org_unit_id is distinct from new.org_unit_id) then
   raise exception 'site_org_reassignment_conflicts_with_active_engagements' using errcode='23514';
 end if;
 return new;
end $$;
create trigger site_engagement_org_guard before update of org_unit_id on core.sites
 for each row execute function private.guard_site_engagement_org_reassignment();

-- Engagement events are derived from database OLD/NEW values and auth context;
-- clients cannot forge actor IDs or edit lifecycle history.
create or replace function private.record_person_engagement_event() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_membership uuid; v_type text; v_before jsonb:='{}'::jsonb; v_after jsonb:='{}'::jsonb;
begin
 select m.id into v_membership from iam.memberships m where m.tenant_id=new.tenant_id
  and m.user_id=v_actor and m.status='active';
 if v_actor is null or v_membership is null then
   raise exception 'verified_company_actor_required' using errcode='42501';
 end if;
 if tg_op='INSERT' then
   v_type:='created';
   v_after:=jsonb_build_object('engagement_type',new.engagement_type,'contractor_organization_id',new.contractor_organization_id,
     'site_id',new.site_id,'org_unit_id',new.org_unit_id,'starts_at',new.starts_at,'ends_at',new.ends_at,'status',new.status);
 else
   v_before:=jsonb_strip_nulls(jsonb_build_object('engagement_type',old.engagement_type,'contractor_organization_id',old.contractor_organization_id,
     'site_id',old.site_id,'org_unit_id',old.org_unit_id,'starts_at',old.starts_at,'ends_at',old.ends_at,'status',old.status));
   v_after:=jsonb_strip_nulls(jsonb_build_object('engagement_type',new.engagement_type,'contractor_organization_id',new.contractor_organization_id,
     'site_id',new.site_id,'org_unit_id',new.org_unit_id,'starts_at',new.starts_at,'ends_at',new.ends_at,'status',new.status));
   if new.status='ended' and old.status<>'ended' then v_type:='ended';
   elsif new.status='cancelled' and old.status<>'cancelled' then v_type:='cancelled';
   elsif new.site_id is distinct from old.site_id then v_type:='site_changed';
   elsif new.org_unit_id is distinct from old.org_unit_id then v_type:='org_unit_changed';
   elsif new.contractor_organization_id is distinct from old.contractor_organization_id then v_type:='contractor_organization_changed';
   elsif new.engagement_type is distinct from old.engagement_type then v_type:='engagement_type_changed';
   elsif new.status is distinct from old.status then v_type:='status_changed';
   else v_type:='updated'; end if;
 end if;
 insert into hse.person_engagement_events(tenant_id,person_id,engagement_id,event_type,actor_user_id,actor_membership_id,
   before_values,after_values,request_id)
 values(new.tenant_id,new.person_id,new.id,v_type,v_actor,v_membership,v_before,v_after,
   nullif(current_setting('request.headers',true)::jsonb->>'x-request-id',''));
 return new;
end $$;
create trigger person_engagement_event_after_insert after insert on hse.person_engagements
 for each row execute function private.record_person_engagement_event();
create trigger person_engagement_event_after_update after update on hse.person_engagements
 for each row when (to_jsonb(new)-array['updated_at'] is distinct from to_jsonb(old)-array['updated_at'])
 execute function private.record_person_engagement_event();
create or replace function private.reject_person_engagement_event_mutation() returns trigger
language plpgsql set search_path='' as $$
begin raise exception 'person_engagement_history_is_append_only' using errcode='42501'; end $$;
create trigger person_engagement_event_immutable before update or delete on hse.person_engagement_events
 for each row execute function private.reject_person_engagement_event_mutation();

create or replace function private.audit_people_row_change() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_tenant uuid; v_id uuid; v_action text; v_changed jsonb:='{}'::jsonb; v_before jsonb:='{}'::jsonb; v_after jsonb:='{}'::jsonb;
begin
 v_tenant:=case when tg_op='DELETE' then old.tenant_id else new.tenant_id end;
 v_id:=case when tg_op='DELETE' then old.id else new.id end;
 v_action:='hse.people.'||lower(tg_op);
 if tg_op='UPDATE' then
   select coalesce(jsonb_object_agg(k,true),'{}'::jsonb) into v_changed from jsonb_each(to_jsonb(new)) n(k,nv)
    join jsonb_each(to_jsonb(old)) o(k,ov) using(k) where n.nv is distinct from o.ov and k not in ('updated_at');
 end if;
 insert into audit.events(tenant_id,actor_user_id,action_key,record_type,record_id,summary)
 values(v_tenant,auth.uid(),v_action,tg_table_schema||'.'||tg_table_name,v_id,
   jsonb_build_object('changed_fields',v_changed));
 if tg_op='DELETE' then return old; end if;
 return new;
end $$;
create trigger people_audit after insert or update on hse.people for each row execute function private.audit_people_row_change();
create trigger contractor_organizations_audit after insert or update on hse.contractor_organizations for each row execute function private.audit_people_row_change();

-- Strict company-only membership lookup. Platform status is never a substitute
-- for active membership on the Phase 1 People surface.
create or replace function private.phase1_membership(p_tenant_id uuid)
returns uuid language sql stable security definer set search_path='' as $$
 select m.id from iam.memberships m join core.tenants t on t.id=m.tenant_id
 where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
$$;



create or replace function private.people_scope_allowed(p_tenant_id uuid,p_membership_id uuid,p_site_id uuid,p_org_unit_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.id=p_membership_id
          and m.member_role='company_superadmin')
    or ((p_site_id is null or exists(select 1 from iam.site_access sa where sa.tenant_id=p_tenant_id
          and sa.membership_id=p_membership_id and sa.site_id=p_site_id and sa.active))
    and (p_org_unit_id is null or exists(select 1 from iam.org_unit_access oa where oa.tenant_id=p_tenant_id
          and oa.membership_id=p_membership_id and oa.org_unit_id=p_org_unit_id and oa.active)))
$$;

create or replace function private.people_delegation_allows(p_tenant_id uuid,p_actor_membership uuid,p_capability text,
 p_target_membership uuid,p_site_id uuid,p_org_unit_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1 from iam.delegation_envelopes d
   join iam.memberships grantor on grantor.tenant_id=d.tenant_id and grantor.id=d.grantor_membership_id
   join iam.memberships delegate on delegate.tenant_id=d.tenant_id and delegate.id=d.delegate_membership_id
   join core.tenants t on t.id=d.tenant_id
   where d.tenant_id=p_tenant_id and d.delegate_membership_id=p_actor_membership
     and d.status='active' and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and t.status='active' and grantor.status='active' and delegate.status='active'
     and p_capability=any(d.allowed_capabilities)
     and (p_target_membership is null or p_target_membership=d.delegate_membership_id
        or exists(select 1 from iam.memberships target where target.tenant_id=d.tenant_id and target.id=p_target_membership
          and ((d.level='employees_default' and target.member_role='employee')
            or d.level='tenant'
            or (d.level='site' and p_site_id=d.site_id and exists(select 1 from iam.site_access sa where sa.tenant_id=d.tenant_id and sa.membership_id=target.id and sa.site_id=d.site_id and sa.active))
            or (d.level='org_unit' and p_org_unit_id=d.org_unit_id and exists(select 1 from iam.org_unit_access oa where oa.tenant_id=d.tenant_id and oa.membership_id=target.id and oa.org_unit_id=d.org_unit_id and oa.active)))))
     and (d.level='tenant' or d.level='employees_default'
       or (d.level='site' and p_site_id=d.site_id)
       or (d.level='org_unit' and p_org_unit_id=d.org_unit_id))
     and (grantor.member_role='company_superadmin' or exists(
       select 1 from iam.delegation_envelopes parent where parent.tenant_id=d.tenant_id
         and parent.delegate_membership_id=d.grantor_membership_id and parent.status='active'
         and parent.starts_at<=now() and (parent.ends_at is null or now()<parent.ends_at)
         and p_capability=any(parent.allowed_capabilities)))
 )
$$;

create or replace function private.phase1_can_manage(p_tenant_id uuid,p_capability text,p_target_membership uuid default null,
 p_site_id uuid default null,p_org_unit_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
   where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
     and private.has_module_entitlement(p_tenant_id,'hse')
     and ((m.member_role='company_superadmin' and not exists(select 1 from iam.superadmin_capability_limits l
       where l.tenant_id=m.tenant_id and l.membership_id=m.id and l.capability_key=p_capability and l.can_delegate=false))
       or private.people_delegation_allows(p_tenant_id,m.id,p_capability,p_target_membership,p_site_id,p_org_unit_id)))
$$;

create or replace function private.phase1_permission_allowed(p_tenant_id uuid,p_permission_key text,p_site_id uuid default null,
 p_org_unit_id uuid default null,p_write boolean default false,p_task_kind text default null,p_task_id uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 with actor as (
   select m.id,m.member_role from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and private.has_module_entitlement(p_tenant_id,'hse')
 ), catalog as (
   select pc.permission_key,pc.enabled,pc.feature_key from iam.permission_catalog pc
    where pc.permission_key=p_permission_key and pc.module_key='hse'
 ), grants as (
   select rp.scope_kind, null::uuid site_id, null::uuid org_unit_id, null::uuid task_id, mr.id assignment_id
   from actor a join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id
   join iam.roles r on r.id=mr.role_id and r.active
   join iam.role_versions rv on rv.tenant_id=mr.tenant_id and rv.id=mr.role_version_id and rv.role_id=mr.role_id and rv.status='published'
   join iam.role_version_permissions rp on rp.role_version_id=rv.id and rp.permission_key=p_permission_key
   where mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select rp.scope_kind, null::uuid, null::uuid, null::uuid, mr.id
   from actor a join iam.membership_roles mr on mr.tenant_id=p_tenant_id and mr.membership_id=a.id and mr.role_version_id is null
   join iam.roles r on r.id=mr.role_id and r.active
   join iam.role_permissions rp on rp.role_id=r.id and rp.permission_key=p_permission_key and rp.active
   where mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
     and (case when p_write then rp.can_write else rp.can_read or rp.can_write end)
   union all
   select pp.scope_kind,pp.site_id,pp.org_unit_id,null::uuid,null::uuid
   from actor a join iam.membership_permission_profiles mp on mp.tenant_id=p_tenant_id and mp.membership_id=a.id and mp.is_current
   join iam.permission_profiles p on p.tenant_id=mp.tenant_id and p.id=mp.profile_id and p.active
   join iam.permission_profile_versions pv on pv.tenant_id=mp.tenant_id and pv.id=mp.profile_version_id and pv.profile_id=p.id
   join iam.permission_profile_permissions pp on pp.tenant_id=p.tenant_id and pp.profile_version_id=pv.id and pp.permission_key=p_permission_key
   where (case when p_write then pp.can_write else pp.can_read or pp.can_write end)
   union all
   select d.scope_kind,d.site_id,d.org_unit_id,d.task_id,null::uuid
   from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='allow' and d.status='active'
     and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at) and (case when p_write then d.can_write else d.can_read or d.can_write end)
 ), denies as (
   select d.* from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
   where d.permission_key=p_permission_key and d.decision='deny' and d.status='active'
     and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
     and (d.scope_kind='tenant' or (d.scope_kind='site' and d.site_id=p_site_id)
       or (d.scope_kind='org_unit' and d.org_unit_id=p_org_unit_id)
       or (d.scope_kind='assigned_task' and d.task_kind=p_task_kind and d.task_id=p_task_id))
 ), override as (
   select exists(select 1 from actor a join iam.member_permission_decisions d on d.tenant_id=p_tenant_id and d.membership_id=a.id
    where d.permission_key=p_permission_key and d.decision='allow' and d.exception_kind='specific_override'
      and d.status='active' and d.starts_at<=now() and (d.ends_at is null or now()<d.ends_at)
      and private.phase1_can_manage(p_tenant_id,'permissions.specific_override',a.id,p_site_id,p_org_unit_id)) as allowed
 )
 select coalesce((
   select c.enabled and exists(select 1 from actor)
     and (c.feature_key is null or private.has_feature_entitlement(p_tenant_id,(select id from actor),c.feature_key))
     and (private.has_module_entitlement(p_tenant_id,'hse'))
     and private.people_scope_allowed(p_tenant_id,(select id from actor),p_site_id,p_org_unit_id)
     and (
       ((select member_role='company_superadmin' from actor) and not exists(select 1 from iam.superadmin_capability_limits l
         where l.tenant_id=p_tenant_id and l.membership_id=(select id from actor)
           and l.capability_key=p_permission_key and l.can_use=false))
       or exists(select 1 from grants g where
         (g.scope_kind='tenant')
         or (g.scope_kind='site' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_sites rs
             where rs.tenant_id=p_tenant_id and rs.membership_role_id=g.assignment_id and rs.site_id=p_site_id
               and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
           or (g.assignment_id is null and g.site_id=p_site_id)))
         or (g.scope_kind='org_unit' and ((g.assignment_id is not null and exists(select 1 from iam.membership_role_org_units ro
             where ro.tenant_id=p_tenant_id and ro.membership_role_id=g.assignment_id and ro.org_unit_id=p_org_unit_id
               and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
           or (g.assignment_id is null and g.org_unit_id=p_org_unit_id)))
         or (g.scope_kind='assigned_task' and p_task_id is not null
             and exists(select 1 from iam.task_assignments ta where ta.tenant_id=p_tenant_id
               and ta.membership_id=(select id from actor) and ta.task_kind=p_task_kind and ta.task_id=p_task_id
               and ta.active and (ta.site_id is null or ta.site_id=p_site_id) and (ta.org_unit_id is null or ta.org_unit_id=p_org_unit_id)))
       )
     )
     and (not exists(select 1 from denies) or (select allowed from override))
   from catalog c
 ),false)
$$;

-- Strict Phase 1 surface. These policies never use legacy platform or
-- company-superadmin short-circuit helpers.
alter table hse.people enable row level security;
alter table hse.people force row level security;
alter table hse.contractor_organizations enable row level security;
alter table hse.contractor_organizations force row level security;
alter table hse.person_engagements enable row level security;
alter table hse.person_engagements force row level security;
alter table hse.person_engagement_events enable row level security;
alter table hse.person_engagement_events force row level security;

create or replace function private.guard_people_membership_link() returns trigger
language plpgsql security definer set search_path='' as $$
begin
 if new.membership_id is not null and (tg_op='INSERT' or new.membership_id is distinct from old.membership_id)
    and not private.phase1_permission_allowed(
    new.tenant_id,'membership_link',null,null,true) then
   raise exception 'people_membership_link_not_allowed' using errcode='42501';
 end if;
 return new;
end $$;
create trigger people_membership_link_guard before insert or update of membership_id on hse.people
 for each row execute function private.guard_people_membership_link();

create policy people_select on hse.people for select to authenticated
 using(private.phase1_permission_allowed(tenant_id,'view_all',null,null,false));
create policy people_insert on hse.people for insert to authenticated
 with check(created_by=auth.uid() and private.phase1_permission_allowed(tenant_id,'create_edit',null,null,true));
create policy people_update on hse.people for update to authenticated
 using(private.phase1_permission_allowed(tenant_id,'create_edit',null,null,true))
 with check(private.phase1_permission_allowed(tenant_id,'create_edit',null,null,true));

create policy contractor_org_select on hse.contractor_organizations for select to authenticated
 using(private.phase1_permission_allowed(tenant_id,'contractors',null,null,false));
create policy contractor_org_insert on hse.contractor_organizations for insert to authenticated
 with check(created_by=auth.uid() and private.phase1_permission_allowed(tenant_id,'contractors',null,null,true));
create policy contractor_org_update on hse.contractor_organizations for update to authenticated
 using(private.phase1_permission_allowed(tenant_id,'contractors',null,null,true))
 with check(private.phase1_permission_allowed(tenant_id,'contractors',null,null,true));

create policy engagement_select on hse.person_engagements for select to authenticated
 using(private.phase1_permission_allowed(tenant_id,'engagements',site_id,org_unit_id,false));
create policy engagement_insert on hse.person_engagements for insert to authenticated
 with check(created_by=auth.uid() and private.phase1_permission_allowed(tenant_id,'engagements',site_id,org_unit_id,true));
create policy engagement_update on hse.person_engagements for update to authenticated
 using(private.phase1_permission_allowed(tenant_id,'engagements',site_id,org_unit_id,true))
 with check(private.phase1_permission_allowed(tenant_id,'engagements',site_id,org_unit_id,true));

create policy engagement_event_select on hse.person_engagement_events for select to authenticated
 using(private.phase1_permission_allowed(tenant_id,'engagements',
   (select e.site_id from hse.person_engagements e where e.tenant_id=person_engagement_events.tenant_id and e.id=engagement_id),
   (select e.org_unit_id from hse.person_engagements e where e.tenant_id=person_engagement_events.tenant_id and e.id=engagement_id),false));

revoke all on hse.people,hse.contractor_organizations,hse.person_engagements,hse.person_engagement_events from anon,authenticated,service_role;
grant select,insert,update on hse.people,hse.contractor_organizations,hse.person_engagements to authenticated;
grant select on hse.person_engagement_events to authenticated;
grant select,insert,update on hse.people,hse.contractor_organizations,hse.person_engagements to service_role;
grant select on hse.person_engagement_events to service_role;
revoke all on function private.phase1_membership(uuid),private.people_scope_allowed(uuid,uuid,uuid,uuid),
 private.people_delegation_allows(uuid,uuid,text,uuid,uuid,uuid),private.phase1_can_manage(uuid,text,uuid,uuid,uuid),
 private.phase1_permission_allowed(uuid,text,uuid,uuid,boolean,text,uuid) from public,anon,authenticated,service_role;
grant execute on function private.phase1_membership(uuid),private.people_scope_allowed(uuid,uuid,uuid,uuid),
 private.phase1_permission_allowed(uuid,text,uuid,uuid,boolean,text,uuid) to authenticated,service_role;

commit;
