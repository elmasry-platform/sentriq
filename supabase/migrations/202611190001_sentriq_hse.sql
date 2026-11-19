-- Initial SENTRIQ schema for Supabase PostgreSQL.
-- Company data is tenant-scoped. Platform operators are separate from company roles.
begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists core;
create schema if not exists iam;
create schema if not exists hse;
create schema if not exists audit;
create schema if not exists api;
create schema if not exists private;

create table iam.platform_operators (
  user_id uuid primary key references auth.users(id) on delete restrict,
  operator_role text not null check (operator_role in ('owner','subowner')),
  active boolean not null default true,
  created_by uuid references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  deactivated_at timestamptz,
  check ((operator_role = 'owner') = (created_by is null)),
  check ((active and deactivated_at is null) or (not active and deactivated_at is not null))
);
create unique index platform_single_active_owner on iam.platform_operators(operator_role)
  where operator_role = 'owner' and active;

create table core.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 1 and 200),
  industry_label text,
  status text not null default 'active' check (status in ('active','suspended','closed')),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);
create table core.org_units (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  parent_id uuid, name text not null check (length(btrim(name)) between 1 and 200),
  created_at timestamptz not null default now(), unique (tenant_id,id),
  foreign key (tenant_id,parent_id) references core.org_units(tenant_id,id) on delete restrict
);
create table core.sites (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  org_unit_id uuid, name text not null check (length(btrim(name)) between 1 and 200),
  code text not null check (length(btrim(code)) between 1 and 40), city text,
  status text not null default 'active' check (status in ('active','inactive')),
  created_at timestamptz not null default now(), unique (tenant_id,id), unique (tenant_id,code),
  foreign key (tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict
);
create table core.tenant_domains (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  domain_name text not null check (domain_name=lower(btrim(domain_name)) and domain_name ~ '^[a-z0-9.-]+$'),
  status text not null default 'pending' check (status in ('pending','verified','disabled')),
  verified_at timestamptz, created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), unique (domain_name), unique (tenant_id,id),
  check ((status='verified') = (verified_at is not null))
);
create table core.modules (
  module_key text primary key, label text not null, enabled boolean not null default true
);
create table core.tenant_entitlements (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  module_key text not null references core.modules(module_key) on delete restrict,
  status text not null default 'active' check (status in ('active','suspended')),
  valid_to timestamptz, changed_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), unique (tenant_id,module_key)
);
insert into core.modules(module_key,label) values ('core','Company structure'),('hse','Health, Safety and Environment'),('operations','Operations');

create table iam.memberships (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete restrict,
  member_role text not null check (member_role in ('company_superadmin','company_admin','employee')),
  status text not null default 'active' check (status in ('invited','active','suspended','ended')),
  display_name text, email text check (email is null or (email=lower(btrim(email)) and length(email)<=254)),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id,id), unique (tenant_id,user_id)
);
create unique index one_active_company_superadmin on iam.memberships(tenant_id)
  where member_role = 'company_superadmin' and status = 'active';
create table iam.site_access (
  tenant_id uuid not null, membership_id uuid not null, site_id uuid not null,
  granted_by uuid not null references auth.users(id) on delete restrict, active boolean not null default true,
  created_at timestamptz not null default now(),
  primary key (tenant_id,membership_id,site_id),
  foreign key (tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete cascade,
  foreign key (tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict
);
create table iam.permission_catalog (
  permission_key text primary key, module_key text not null, label text not null,
  description text, enabled boolean not null default true
);
create table iam.member_permissions (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, membership_id uuid not null,
  permission_key text not null references iam.permission_catalog(permission_key) on delete restrict,
  scope_kind text not null check (scope_kind in ('tenant','site','assigned_task')),
  site_id uuid, can_read boolean not null default false, can_write boolean not null default false,
  granted_by uuid not null references auth.users(id) on delete restrict, active boolean not null default true,
  created_at timestamptz not null default now(),
  check ((can_read or can_write) or not active), check ((scope_kind = 'site') = (site_id is not null)),
  foreign key (tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete cascade,
  foreign key (tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict
);
create unique index member_permission_unique on iam.member_permissions
  (tenant_id,membership_id,permission_key,scope_kind,coalesce(site_id,'00000000-0000-0000-0000-000000000000'::uuid));
create table iam.task_assignments (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, membership_id uuid not null,
  task_kind text not null check (task_kind in ('inspection','review','finding','action','follow_up')),
  task_id uuid not null, assigned_by uuid not null references auth.users(id) on delete restrict,
  active boolean not null default true, created_at timestamptz not null default now(), unique (tenant_id,membership_id,task_kind,task_id),
  foreign key (tenant_id,membership_id) references iam.memberships(tenant_id,id) on delete cascade
);

insert into iam.permission_catalog(permission_key,module_key,label) values
 ('core.structure.manage','core','Manage company sites and organization units'),
 ('hse.dashboard.read','hse','View HSE dashboard'), ('hse.forms.read','hse','View forms'),
 ('hse.forms.manage','hse','Create and publish forms'), ('hse.inspections.read','hse','View inspections'),
 ('hse.inspections.create','hse','Create and update inspections'), ('hse.inspections.review','hse','Review assigned inspections'),
 ('hse.inspections.review.reviewer_1','hse','Perform first-stage inspection review'),
 ('hse.inspections.review.reviewer_2','hse','Perform second-stage inspection review'),
 ('hse.inspections.review.final_reviewer','hse','Perform final inspection review'),
 ('hse.findings.read','hse','View findings'), ('hse.findings.manage','hse','Manage findings'),
 ('hse.actions.read','hse','View corrective actions'), ('hse.actions.update_assigned','hse','Update assigned actions'),
 ('hse.actions.manage','hse','Manage corrective actions'), ('hse.actions.close_review','hse','Review action closure'),
 ('hse.evidence.read','hse','View evidence'), ('hse.evidence.upload','hse','Upload evidence'),
 ('hse.audit.read','hse','View audit events');

create table hse.form_templates (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  title jsonb not null check (jsonb_typeof(title) = 'object'), category text not null,
  status text not null default 'draft' check (status in ('draft','published','archived')),
  revision integer not null default 1 check (revision > 0),
  definition jsonb not null default '{}'::jsonb check (jsonb_typeof(definition) = 'object'),
  owner_membership_id uuid not null, created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id,id),
  foreign key (tenant_id,owner_membership_id) references iam.memberships(tenant_id,id) on delete restrict
);
create table hse.form_versions (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, template_id uuid not null,
  version integer not null check (version > 0), snapshot jsonb not null check (jsonb_typeof(snapshot) = 'object'),
  published_by uuid not null references auth.users(id) on delete restrict, published_at timestamptz not null default now(),
  unique (tenant_id,id), unique (tenant_id,template_id,id), unique (tenant_id,template_id,version),
  foreign key (tenant_id,template_id) references hse.form_templates(tenant_id,id) on delete restrict
);
create table hse.inspections (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null references core.tenants(id) on delete restrict,
  site_id uuid not null, template_id uuid not null, form_version_id uuid not null,
  title text not null, inspector_membership_id uuid not null,
  status text not null default 'draft' check (status in ('draft','submitted','in_review','returned','approved')),
  current_stage text check (current_stage in ('reviewer_1','reviewer_2','final_reviewer')),
  answers jsonb not null default '[]'::jsonb check (jsonb_typeof(answers) = 'array'),
  revision integer not null default 1 check (revision > 0), created_at timestamptz not null default now(),
  submitted_at timestamptz, updated_at timestamptz not null default now(), unique (tenant_id,id), unique (tenant_id,id,site_id),
  foreign key (tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
  foreign key (tenant_id,template_id) references hse.form_templates(tenant_id,id) on delete restrict,
  foreign key (tenant_id,template_id,form_version_id) references hse.form_versions(tenant_id,template_id,id) on delete restrict,
  foreign key (tenant_id,inspector_membership_id) references iam.memberships(tenant_id,id) on delete restrict,
  check ((status in ('submitted','in_review','returned','approved')) = (submitted_at is not null))
);
create table hse.inspection_reviews (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, inspection_id uuid not null,
  stage text not null check (stage in ('reviewer_1','reviewer_2','final_reviewer')),
  decision text not null check (decision in ('approved','returned')), actor_membership_id uuid,
  actor_user_id uuid not null references auth.users(id) on delete restrict,
  reason text, revision integer not null check (revision > 0), created_at timestamptz not null default now(),
  foreign key (tenant_id,inspection_id) references hse.inspections(tenant_id,id) on delete restrict,
  foreign key (tenant_id,actor_membership_id) references iam.memberships(tenant_id,id) on delete restrict
);
create table hse.findings (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, site_id uuid not null,
  inspection_id uuid not null, question_id text, title text not null, description text,
  priority text not null default 'medium' check (priority in ('low','medium','high','critical')),
  status text not null default 'open' check (status in ('open','action_created','resolved')),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id,id), unique (tenant_id,id,inspection_id,site_id),
  foreign key (tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
  foreign key (tenant_id,inspection_id) references hse.inspections(tenant_id,id) on delete restrict,
  foreign key (tenant_id,inspection_id,site_id) references hse.inspections(tenant_id,id,site_id) on delete restrict
);
create table hse.corrective_actions (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, site_id uuid not null,
  finding_id uuid not null, inspection_id uuid not null, title text not null, description text,
  owner_membership_id uuid not null, priority text not null default 'medium'
    check (priority in ('low','medium','high','critical')),
  status text not null default 'open' check (status in ('open','in_progress','closure_requested','closed')),
  response_due_at timestamptz, plan_due_at timestamptz, closure_due_at timestamptz,
  revision integer not null default 1 check (revision > 0), created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(), unique (tenant_id,id),
  foreign key (tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
  foreign key (tenant_id,finding_id) references hse.findings(tenant_id,id) on delete restrict,
  foreign key (tenant_id,inspection_id,site_id) references hse.inspections(tenant_id,id,site_id) on delete restrict,
  foreign key (tenant_id,finding_id,inspection_id,site_id) references hse.findings(tenant_id,id,inspection_id,site_id) on delete restrict,
  foreign key (tenant_id,owner_membership_id) references iam.memberships(tenant_id,id) on delete restrict
);
create table hse.action_updates (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, action_id uuid not null,
  actor_membership_id uuid, actor_user_id uuid references auth.users(id) on delete restrict, status text not null
    check (status in ('open','in_progress','closure_requested','closed')),
  comment text, created_at timestamptz not null default now(),
  foreign key (tenant_id,action_id) references hse.corrective_actions(tenant_id,id) on delete restrict,
  foreign key (tenant_id,actor_membership_id) references iam.memberships(tenant_id,id) on delete restrict
);
create table hse.follow_ups (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, action_id uuid not null,
  title text not null, owner_membership_id uuid not null, due_at timestamptz not null,
  status text not null default 'open' check (status in ('open','in_progress','completed','cancelled')),
  outcome text, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (tenant_id,id),
  foreign key (tenant_id,action_id) references hse.corrective_actions(tenant_id,id) on delete restrict,
  foreign key (tenant_id,owner_membership_id) references iam.memberships(tenant_id,id) on delete restrict
);
create table hse.evidence_files (
  id uuid primary key default gen_random_uuid(), tenant_id uuid not null, site_id uuid not null,
  linked_record_type text not null check (linked_record_type in ('inspection','finding','action','follow_up')),
  linked_record_id uuid not null, storage_key text not null, file_name text not null, mime_type text not null,
  size_bytes bigint not null check (size_bytes > 0), status text not null default 'pending'
    check (status in ('pending','confirmed','rejected')),
  uploaded_by uuid not null references auth.users(id) on delete restrict, created_at timestamptz not null default now(),
  unique (tenant_id,storage_key), foreign key (tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict
);
create table audit.events (
  id bigint generated always as identity primary key, tenant_id uuid references core.tenants(id) on delete restrict,
  actor_user_id uuid references auth.users(id) on delete restrict, action_key text not null,
  record_type text not null, record_id uuid, summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index inspections_site_created_idx on hse.inspections(tenant_id,site_id,created_at desc);
create index inspections_status_idx on hse.inspections(tenant_id,status,created_at desc);
create index findings_status_idx on hse.findings(tenant_id,site_id,status);
create index actions_status_idx on hse.corrective_actions(tenant_id,site_id,status);
create index actions_owner_idx on hse.corrective_actions(tenant_id,owner_membership_id,status);
create index follow_ups_due_idx on hse.follow_ups(tenant_id,owner_membership_id,due_at) where status in ('open','in_progress');
create index evidence_link_idx on hse.evidence_files(tenant_id,linked_record_type,linked_record_id);
create index audit_tenant_created_idx on audit.events(tenant_id,created_at desc);

create or replace function private.is_platform_operator() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active)
$$;
create or replace function private.is_platform_owner() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active and p.operator_role = 'owner')
$$;
create or replace function private.can_access_tenant(p_tenant_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select private.is_platform_operator() or exists (
    select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active')
$$;
create or replace function private.can_manage_tenant(p_tenant_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select private.is_platform_operator() or exists (
    select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.member_role='company_superadmin'
      and m.status='active' and t.status='active')
$$;
create or replace function private.can_access_core(p_tenant_id uuid,p_permission text,p_site_id uuid default null,p_write boolean default false)
returns boolean language sql stable security definer set search_path = '' as $$
  select private.is_platform_operator() or exists (
    select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and (m.member_role='company_superadmin' or exists (
        select 1 from iam.member_permissions g where g.tenant_id=m.tenant_id and g.membership_id=m.id
          and g.active and g.permission_key=p_permission
          and (case when p_write then g.can_write else (g.can_read or g.can_write) end)
          and ((g.scope_kind='tenant' and (p_site_id is null or exists (
              select 1 from iam.site_access sa where sa.tenant_id=m.tenant_id and sa.membership_id=m.id
                and sa.site_id=p_site_id and sa.active)))
            or (g.scope_kind='site' and g.site_id=p_site_id and exists (
              select 1 from iam.site_access sa where sa.tenant_id=m.tenant_id and sa.membership_id=m.id
                and sa.site_id=p_site_id and sa.active)))
      ))
  )
$$;
create or replace function private.can_access_hse(
  p_tenant_id uuid, p_permission text, p_site_id uuid default null, p_write boolean default false,
  p_task_kind text default null, p_task_id uuid default null
) returns boolean language sql stable security definer set search_path = '' as $$
  select private.is_platform_operator() or exists (
    select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active' and t.status='active'
      and (m.member_role='company_superadmin' or exists (
        select 1 from iam.member_permissions g where g.tenant_id=m.tenant_id and g.membership_id=m.id
          and g.active and g.permission_key=p_permission and (case when p_write then g.can_write else (g.can_read or g.can_write) end)
          and ((g.scope_kind='tenant' and (p_site_id is null or exists (
              select 1 from iam.site_access sa where sa.tenant_id=m.tenant_id and sa.membership_id=m.id and sa.site_id=p_site_id and sa.active))
            or (g.scope_kind='site' and g.site_id=p_site_id and exists (
              select 1 from iam.site_access sa where sa.tenant_id=m.tenant_id and sa.membership_id=m.id
                and sa.site_id=p_site_id and sa.active))
            or (g.scope_kind='assigned_task' and p_task_id is not null and exists (
              select 1 from iam.task_assignments ta where ta.tenant_id=m.tenant_id and ta.membership_id=m.id
                and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active)))
      ) and exists (select 1 from core.tenant_entitlements e where e.tenant_id=m.tenant_id
        and e.module_key='hse' and e.status='active' and (e.valid_to is null or e.valid_to>now())))))
$$;
create or replace function private.current_membership_id(p_tenant_id uuid) returns uuid
language sql stable security definer set search_path = '' as $$
  select m.id from iam.memberships m where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.status='active'
$$;
create or replace function private.can_review_hse(p_tenant_id uuid,p_site_id uuid,p_task_id uuid,p_write boolean)
returns boolean language sql stable security definer set search_path = '' as $$
  select private.can_access_hse(p_tenant_id,'hse.inspections.review',p_site_id,p_write,'review',p_task_id)
    or private.can_access_hse(p_tenant_id,'hse.inspections.review.reviewer_1',p_site_id,p_write,'review',p_task_id)
    or private.can_access_hse(p_tenant_id,'hse.inspections.review.reviewer_2',p_site_id,p_write,'review',p_task_id)
    or private.can_access_hse(p_tenant_id,'hse.inspections.review.final_reviewer',p_site_id,p_write,'review',p_task_id)
$$;
create or replace function private.guard_inspection_update() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_is_inspector boolean; v_is_reviewer boolean;
begin
  if private.can_manage_tenant(old.tenant_id) then return new; end if;
  v_is_inspector := old.inspector_membership_id=private.current_membership_id(old.tenant_id)
    and private.can_access_hse(old.tenant_id,'hse.inspections.create',old.site_id,true);
  v_is_reviewer := old.current_stage is not null and (
    private.can_access_hse(old.tenant_id,'hse.inspections.review',old.site_id,true,'review',old.id)
    or private.can_access_hse(old.tenant_id,'hse.inspections.review.'||old.current_stage,old.site_id,true,'review',old.id));
  if v_is_inspector then
    if (to_jsonb(new)-array['answers','title','status','revision','updated_at'])
       is distinct from (to_jsonb(old)-array['answers','title','status','revision','updated_at'])
       or not ((old.status in ('draft','returned') and new.status='submitted') or new.status=old.status)
       or (old.status not in ('draft','returned') and (new.answers is distinct from old.answers or new.title is distinct from old.title))
       or (new.current_stage is distinct from old.current_stage and not
         (old.status in ('draft','returned') and new.status='submitted' and new.current_stage='reviewer_1'))
       or new.revision<>old.revision+1 then
      raise exception 'inspection fields or transition are restricted' using errcode='42501';
    end if;
    if old.status in ('draft','returned') and new.status='submitted' then
      new.current_stage := 'reviewer_1';
      new.submitted_at := now();
    end if;
  elsif v_is_reviewer then
    if (to_jsonb(new)-array['status','current_stage','revision','updated_at'])
       is distinct from (to_jsonb(old)-array['status','current_stage','revision','updated_at']) then
      raise exception 'reviewers can only change workflow state' using errcode='42501';
    end if;
    if new.revision<>old.revision+1 or not ((old.status='submitted' and new.status='in_review' and new.current_stage='reviewer_1')
      or (old.status='in_review' and new.status='returned' and new.current_stage=old.current_stage)
      or (old.status='in_review' and new.status='in_review' and
        ((old.current_stage='reviewer_1' and new.current_stage='reviewer_2')
          or (old.current_stage='reviewer_2' and new.current_stage='final_reviewer')))
      or (old.status='in_review' and old.current_stage='final_reviewer' and new.status='approved' and new.current_stage=old.current_stage)) then
      raise exception 'invalid inspection workflow transition' using errcode='23514';
    end if;
  else
    raise exception 'insufficient_privilege' using errcode='42501';
  end if;
  return new;
end $$;
create trigger inspection_update_guard before update on hse.inspections
  for each row execute function private.guard_inspection_update();
create or replace function private.guard_inspection_insert() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.status='draft' and (new.current_stage is not null or new.submitted_at is not null) then
    raise exception 'draft inspection has invalid workflow fields' using errcode='23514';
  elsif new.status='submitted' and (new.current_stage is distinct from 'reviewer_1' or new.submitted_at is null) then
    raise exception 'submitted inspection must enter reviewer_1' using errcode='23514';
  elsif new.status not in ('draft','submitted') then
    raise exception 'inspection must start as draft or submitted' using errcode='23514';
  end if;
  if new.revision<>1 then raise exception 'new inspection revision must be 1' using errcode='23514'; end if;
  if not private.can_manage_tenant(new.tenant_id)
     and new.inspector_membership_id is distinct from private.current_membership_id(new.tenant_id) then
    raise exception 'employees can only create their own inspections' using errcode='42501';
  end if;
  return new;
end $$;
create trigger inspection_insert_guard before insert on hse.inspections
  for each row execute function private.guard_inspection_insert();
create or replace function private.apply_inspection_review() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_rows integer;
begin
  update hse.inspections set
    status=case when new.decision='returned' then 'returned'
      when new.stage='final_reviewer' then 'approved' else 'in_review' end,
    current_stage=case when new.decision='returned' or new.stage='final_reviewer' then new.stage
      when new.stage='reviewer_1' then 'reviewer_2' else 'final_reviewer' end,
    revision=revision+1, updated_at=now()
  where tenant_id=new.tenant_id and id=new.inspection_id
    and current_stage=new.stage and status in ('submitted','in_review') and revision=new.revision;
  get diagnostics v_rows = row_count;
  if v_rows<>1 then raise exception 'inspection review is stale' using errcode='40001'; end if;
  return new;
end $$;
create trigger inspection_review_apply after insert on hse.inspection_reviews
  for each row execute function private.apply_inspection_review();
create or replace function private.guard_action_update() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_manage boolean; v_assigned boolean; v_closure boolean;
begin
  if private.can_manage_tenant(old.tenant_id) then return new; end if;
  v_manage := private.can_access_hse(old.tenant_id,'hse.actions.manage',old.site_id,true);
  if v_manage then return new; end if;
  v_closure := private.can_access_hse(old.tenant_id,'hse.actions.close_review',old.site_id,true);
  v_assigned := private.can_access_hse(old.tenant_id,'hse.actions.update_assigned',old.site_id,true,'action',old.id);
  if v_closure and old.status='closure_requested' and new.status in ('closed','in_progress') then
    if (to_jsonb(new)-array['status','revision','updated_at']) is distinct from (to_jsonb(old)-array['status','revision','updated_at']) then
      raise exception 'closure reviewers can only approve or return closure' using errcode='42501';
    end if;
  elsif v_assigned then
    if (to_jsonb(new)-array['status','revision','updated_at']) is distinct from (to_jsonb(old)-array['status','revision','updated_at'])
      or not ((old.status='open' and new.status='in_progress')
        or (old.status='in_progress' and new.status='closure_requested')
        or (old.status='closure_requested' and new.status='in_progress') or new.status=old.status) then
      raise exception 'assigned action fields or transition are restricted' using errcode='42501';
    end if;
  else
    raise exception 'insufficient_privilege' using errcode='42501';
  end if;
  return new;
end $$;
create trigger action_update_guard before update on hse.corrective_actions
  for each row execute function private.guard_action_update();
create or replace function private.record_action_status() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op='INSERT' then
    insert into hse.action_updates(tenant_id,action_id,actor_membership_id,actor_user_id,status)
    values (new.tenant_id,new.id,private.current_membership_id(new.tenant_id),auth.uid(),new.status);
  elsif new.status is distinct from old.status then
    insert into hse.action_updates(tenant_id,action_id,actor_membership_id,actor_user_id,status)
    values (new.tenant_id,new.id,private.current_membership_id(new.tenant_id),auth.uid(),new.status);
  end if;
  return new;
end $$;
create trigger action_status_history after insert or update of status on hse.corrective_actions
  for each row execute function private.record_action_status();

-- The owner is installed exactly once by an operator after creating the owner's Auth account.
create or replace function private.bootstrap_platform_owner(p_user_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if current_user <> 'postgres' then raise exception 'operator only' using errcode='42501'; end if;
  if exists (select 1 from iam.platform_operators where operator_role='owner' and active) then
    raise exception 'owner already provisioned' using errcode='23505';
  end if;
  insert into iam.platform_operators(user_id,operator_role) values (p_user_id,'owner');
end $$;
create or replace function private.guard_membership_role_change() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.member_role is distinct from old.member_role
     and (new.member_role = 'company_superadmin' or old.member_role = 'company_superadmin')
     and not private.is_platform_operator() then
    raise exception 'only a platform operator can change company_superadmin role' using errcode='42501';
  end if;
  return new;
end $$;
create trigger membership_role_guard before update of member_role on iam.memberships
  for each row execute function private.guard_membership_role_change();
create or replace function private.guard_membership_identity() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.tenant_id is distinct from old.tenant_id or new.user_id is distinct from old.user_id then
    raise exception 'membership identity is immutable' using errcode='23514';
  end if;
  if old.member_role='company_superadmin' and old.status='active' and new.status<>'active'
     and not private.is_platform_operator() then
    raise exception 'only a platform operator can deactivate the company superadmin' using errcode='42501';
  end if;
  return new;
end $$;
create trigger membership_identity_guard before update on iam.memberships
  for each row execute function private.guard_membership_identity();
create or replace function private.guard_tenant_id_change() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.tenant_id is distinct from old.tenant_id then
    raise exception 'tenant_id is immutable' using errcode='23514';
  end if;
  return new;
end $$;
create or replace function private.guard_immutable_fields() returns trigger
language plpgsql set search_path = '' as $$
declare i integer;
begin
  for i in 0..tg_nargs-1 loop
    if (to_jsonb(new)->tg_argv[i]) is distinct from (to_jsonb(old)->tg_argv[i]) then
      raise exception 'immutable field changed' using errcode='23514';
    end if;
  end loop;
  return new;
end $$;
create trigger form_created_by_immutable before update on hse.form_templates
  for each row execute function private.guard_immutable_fields('created_by');
create trigger tenant_creator_immutable before update on core.tenants
  for each row execute function private.guard_immutable_fields('created_by');
create trigger domain_creator_immutable before update on core.tenant_domains
  for each row execute function private.guard_immutable_fields('created_by');
create trigger version_publisher_immutable before update on hse.form_versions
  for each row execute function private.guard_immutable_fields('published_by');
create trigger finding_creator_immutable before update on hse.findings
  for each row execute function private.guard_immutable_fields('created_by');
create trigger action_creator_immutable before update on hse.corrective_actions
  for each row execute function private.guard_immutable_fields('created_by');
create trigger evidence_uploader_immutable before update on hse.evidence_files
  for each row execute function private.guard_immutable_fields('uploaded_by');
create trigger evidence_metadata_immutable before update on hse.evidence_files
  for each row execute function private.guard_immutable_fields('tenant_id','site_id','linked_record_type','linked_record_id','storage_key','file_name','mime_type','size_bytes');
create trigger site_grantor_immutable before update on iam.site_access
  for each row execute function private.guard_immutable_fields('granted_by');
create trigger permission_grantor_immutable before update on iam.member_permissions
  for each row execute function private.guard_immutable_fields('granted_by');
create trigger task_assignor_immutable before update on iam.task_assignments
  for each row execute function private.guard_immutable_fields('assigned_by');
create or replace function private.touch_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at = now();
  return new;
end $$;
create or replace function private.path_uuid(p_value text) returns uuid
language plpgsql immutable set search_path = '' as $$
begin
  return p_value::uuid;
exception when others then
  return null;
end $$;
do $$ declare r record; begin
  for r in select table_schema,table_name from information_schema.columns
    where table_schema in ('core','iam','hse','audit') and column_name='tenant_id'
  loop
    execute format('create trigger tenant_id_immutable before update of tenant_id on %I.%I for each row execute function private.guard_tenant_id_change()',r.table_schema,r.table_name);
  end loop;
end $$;
do $$ declare r record; begin
  for r in select table_schema,table_name from information_schema.columns
    where table_schema in ('core','iam','hse','audit') and column_name='updated_at'
  loop
    execute format('create trigger set_updated_at before update on %I.%I for each row execute function private.touch_updated_at()',r.table_schema,r.table_name);
  end loop;
end $$;
create or replace function api.manage_subowner(p_user_id uuid,p_active boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not private.is_platform_owner() then raise exception 'insufficient_privilege' using errcode='42501'; end if;
  if p_active then
    insert into iam.platform_operators(user_id,operator_role,created_by) values (p_user_id,'subowner',auth.uid())
    on conflict (user_id) do update set active=true,deactivated_at=null
      where iam.platform_operators.operator_role='subowner';
  else
    update iam.platform_operators set active=false,deactivated_at=now()
      where user_id=p_user_id and operator_role='subowner' and active;
  end if;
  insert into audit.events(tenant_id,actor_user_id,action_key,record_type,record_id,summary)
    values (null,auth.uid(),case when p_active then 'platform.subowner.activated' else 'platform.subowner.deactivated' end,
      'platform_operator',p_user_id,jsonb_build_object('active',p_active));
end $$;
create or replace function api.create_tenant(p_name text,p_industry_label text,p_company_superadmin uuid) returns uuid
language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  if not private.is_platform_operator() then raise exception 'insufficient_privilege' using errcode='42501'; end if;
  if not exists (select 1 from auth.users u where u.id=p_company_superadmin) then raise exception 'company_superadmin_user_missing' using errcode='22023'; end if;
  insert into core.tenants(name,industry_label,created_by)
    values (btrim(p_name),nullif(btrim(p_industry_label),''),auth.uid()) returning id into v_id;
  insert into iam.memberships(tenant_id,user_id,member_role,status)
    values (v_id,p_company_superadmin,'company_superadmin','active');
  insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by)
    values (v_id,'hse','active',auth.uid());
  return v_id;
end $$;

create or replace function private.validate_evidence_link() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_site_id uuid;
begin
  if new.linked_record_type='inspection' then
    select site_id into v_site_id from hse.inspections where tenant_id=new.tenant_id and id=new.linked_record_id;
  elsif new.linked_record_type='finding' then
    select site_id into v_site_id from hse.findings where tenant_id=new.tenant_id and id=new.linked_record_id;
  elsif new.linked_record_type='action' then
    select site_id into v_site_id from hse.corrective_actions where tenant_id=new.tenant_id and id=new.linked_record_id;
  elsif new.linked_record_type='follow_up' then
    select a.site_id into v_site_id from hse.follow_ups f join hse.corrective_actions a
      on a.tenant_id=f.tenant_id and a.id=f.action_id
      where f.tenant_id=new.tenant_id and f.id=new.linked_record_id;
  end if;
  if v_site_id is null or v_site_id is distinct from new.site_id then
    raise exception 'evidence target is invalid for tenant/site' using errcode='23503';
  end if;
  return new;
end $$;
create trigger evidence_target_guard before insert or update of tenant_id,site_id,linked_record_type,linked_record_id
  on hse.evidence_files for each row execute function private.validate_evidence_link();

-- Force RLS on all application tables, including tables with no authenticated write path.
do $$ declare r record; begin
  for r in select schemaname,tablename from pg_tables where schemaname in ('core','iam','hse','audit') loop
    execute format('alter table %I.%I enable row level security',r.schemaname,r.tablename);
    execute format('alter table %I.%I force row level security',r.schemaname,r.tablename);
  end loop;
end $$;

create policy tenant_read on core.tenants for select to authenticated using (private.can_access_tenant(id));
create policy tenant_update on core.tenants for update to authenticated using (private.is_platform_operator()) with check (private.is_platform_operator());
create policy tenant_domains_read on core.tenant_domains for select to authenticated using (private.is_platform_operator());
create policy tenant_domains_insert on core.tenant_domains for insert to authenticated with check (private.is_platform_operator() and created_by=auth.uid());
create policy tenant_domains_update on core.tenant_domains for update to authenticated using (private.is_platform_operator()) with check (private.is_platform_operator());
create policy modules_read on core.modules for select to authenticated using (enabled);
create policy entitlements_read on core.tenant_entitlements for select to authenticated using (private.can_access_tenant(tenant_id));
create policy entitlements_insert on core.tenant_entitlements for insert to authenticated with check (private.is_platform_operator() and changed_by=auth.uid());
create policy entitlements_update on core.tenant_entitlements for update to authenticated using (private.is_platform_operator()) with check (private.is_platform_operator() and changed_by=auth.uid());
create policy org_read on core.org_units for select to authenticated using (private.can_access_tenant(tenant_id));
create policy org_write on core.org_units for all to authenticated using (private.can_access_core(tenant_id,'core.structure.manage',null,true)) with check (private.can_access_core(tenant_id,'core.structure.manage',null,true));
create policy site_read on core.sites for select to authenticated using (
  private.can_access_core(tenant_id,'core.structure.manage') or private.is_platform_operator() or exists (
    select 1 from iam.memberships m join iam.site_access sa on sa.tenant_id=m.tenant_id and sa.membership_id=m.id
    where m.tenant_id=sites.tenant_id and m.user_id=auth.uid() and m.status='active' and sa.site_id=sites.id and sa.active));
create policy site_insert on core.sites for insert to authenticated with check (private.can_access_core(tenant_id,'core.structure.manage',null,true));
create policy site_update on core.sites for update to authenticated using (private.can_access_core(tenant_id,'core.structure.manage',id,true)) with check (private.can_access_core(tenant_id,'core.structure.manage',id,true));
create policy membership_read on iam.memberships for select to authenticated using (
  user_id=auth.uid() or private.can_manage_tenant(tenant_id) or private.is_platform_operator());
create policy membership_write on iam.memberships for all to authenticated using (private.can_manage_tenant(tenant_id)) with check (private.can_manage_tenant(tenant_id));
create policy site_access_read on iam.site_access for select to authenticated using (
  private.can_manage_tenant(tenant_id) or exists (select 1 from iam.memberships m where m.id=membership_id and m.user_id=auth.uid()));
create policy site_access_insert on iam.site_access for insert to authenticated with check (private.can_manage_tenant(tenant_id) and granted_by=auth.uid());
create policy site_access_update on iam.site_access for update to authenticated using (private.can_manage_tenant(tenant_id)) with check (private.can_manage_tenant(tenant_id));
create policy permission_read on iam.permission_catalog for select to authenticated using (enabled);
create policy member_permissions_read on iam.member_permissions for select to authenticated using (
  private.can_manage_tenant(tenant_id) or exists (select 1 from iam.memberships m where m.id=membership_id and m.user_id=auth.uid()));
create policy member_permissions_insert on iam.member_permissions for insert to authenticated with check (private.can_manage_tenant(tenant_id) and granted_by=auth.uid());
create policy member_permissions_update on iam.member_permissions for update to authenticated using (private.can_manage_tenant(tenant_id)) with check (private.can_manage_tenant(tenant_id));
create policy task_assignments_read on iam.task_assignments for select to authenticated using (
  private.can_manage_tenant(tenant_id) or exists (select 1 from iam.memberships m where m.id=membership_id and m.user_id=auth.uid()));
create policy task_assignments_insert on iam.task_assignments for insert to authenticated with check (private.can_manage_tenant(tenant_id) and assigned_by=auth.uid());
create policy task_assignments_update on iam.task_assignments for update to authenticated using (private.can_manage_tenant(tenant_id)) with check (private.can_manage_tenant(tenant_id));

create policy forms_read on hse.form_templates for select to authenticated using (private.can_access_hse(tenant_id,'hse.forms.read'));
create policy forms_insert on hse.form_templates for insert to authenticated with check (created_by=auth.uid() and private.can_access_hse(tenant_id,'hse.forms.manage',null,true));
create policy forms_update on hse.form_templates for update to authenticated using (private.can_access_hse(tenant_id,'hse.forms.manage',null,true)) with check (private.can_access_hse(tenant_id,'hse.forms.manage',null,true));
create policy versions_read on hse.form_versions for select to authenticated using (private.can_access_hse(tenant_id,'hse.forms.read'));
create policy versions_insert on hse.form_versions for insert to authenticated with check (published_by=auth.uid() and private.can_access_hse(tenant_id,'hse.forms.manage',null,true));
create policy inspections_read on hse.inspections for select to authenticated using (
  private.can_access_hse(tenant_id,'hse.inspections.read',site_id)
  or private.can_access_hse(tenant_id,'hse.inspections.review',site_id,false,'review',id)
  or private.can_access_hse(tenant_id,'hse.inspections.review.'||coalesce(current_stage,'reviewer_1'),site_id,false,'review',id)
  or (inspector_membership_id=private.current_membership_id(tenant_id)
    and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,false))
  or private.can_access_hse(tenant_id,'hse.inspections.create',site_id,false,'inspection',id));
create policy inspections_insert on hse.inspections for insert to authenticated with check (
  (private.can_manage_tenant(tenant_id) or inspector_membership_id=private.current_membership_id(tenant_id))
  and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true));
create policy inspections_update on hse.inspections for update to authenticated
  using (private.can_manage_tenant(tenant_id) or (inspector_membership_id=private.current_membership_id(tenant_id)
    and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true)))
  with check (private.can_manage_tenant(tenant_id) or (inspector_membership_id=private.current_membership_id(tenant_id)
    and private.can_access_hse(tenant_id,'hse.inspections.create',site_id,true)));
create policy reviews_read on hse.inspection_reviews for select to authenticated using (
  exists (select 1 from hse.inspections i where i.tenant_id=inspection_reviews.tenant_id and i.id=inspection_reviews.inspection_id
    and (private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.read',i.site_id)
      or private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.review',i.site_id,false,'review',i.id)
      or private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.review.'||inspection_reviews.stage,i.site_id,false,'review',i.id))));
create policy reviews_insert on hse.inspection_reviews for insert to authenticated with check (
  actor_user_id=auth.uid() and (actor_membership_id=private.current_membership_id(tenant_id) or private.can_manage_tenant(tenant_id))
  and exists (select 1 from hse.inspections i where i.tenant_id=inspection_reviews.tenant_id and i.id=inspection_reviews.inspection_id
    and i.status in ('submitted','in_review') and i.current_stage=inspection_reviews.stage
    and (private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.review',i.site_id,true,'review',i.id)
      or private.can_access_hse(inspection_reviews.tenant_id,'hse.inspections.review.'||inspection_reviews.stage,i.site_id,true,'review',i.id))));
create policy findings_read on hse.findings for select to authenticated using (
  private.can_access_hse(tenant_id,'hse.findings.read',site_id) or private.can_access_hse(tenant_id,'hse.findings.manage',site_id));
create policy findings_insert on hse.findings for insert to authenticated with check (created_by=auth.uid() and private.can_access_hse(tenant_id,'hse.findings.manage',site_id,true));
create policy findings_update on hse.findings for update to authenticated using (private.can_access_hse(tenant_id,'hse.findings.manage',site_id,true)) with check (private.can_access_hse(tenant_id,'hse.findings.manage',site_id,true));
create policy actions_read on hse.corrective_actions for select to authenticated using (
  private.can_access_hse(tenant_id,'hse.actions.read',site_id) or private.can_access_hse(tenant_id,'hse.actions.manage',site_id)
  or private.can_access_hse(tenant_id,'hse.actions.update_assigned',site_id,false,'action',id)
  or private.can_access_hse(tenant_id,'hse.actions.close_review',site_id));
create policy actions_insert on hse.corrective_actions for insert to authenticated with check (created_by=auth.uid() and private.can_access_hse(tenant_id,'hse.actions.manage',site_id,true));
create policy actions_update on hse.corrective_actions for update to authenticated
  using (private.can_access_hse(tenant_id,'hse.actions.manage',site_id,true) or private.can_access_hse(tenant_id,'hse.actions.update_assigned',site_id,true,'action',id) or private.can_access_hse(tenant_id,'hse.actions.close_review',site_id,true))
  with check (private.can_access_hse(tenant_id,'hse.actions.manage',site_id,true) or private.can_access_hse(tenant_id,'hse.actions.update_assigned',site_id,true,'action',id) or private.can_access_hse(tenant_id,'hse.actions.close_review',site_id,true));
create policy updates_read on hse.action_updates for select to authenticated using (
  exists (select 1 from hse.corrective_actions a where a.tenant_id=action_updates.tenant_id and a.id=action_updates.action_id
    and (private.can_access_hse(action_updates.tenant_id,'hse.actions.read',a.site_id,false,'action',a.id)
      or private.can_access_hse(action_updates.tenant_id,'hse.actions.update_assigned',a.site_id,false,'action',a.id))));
create policy followups_read on hse.follow_ups for select to authenticated using (
  exists (select 1 from hse.corrective_actions a where a.tenant_id=follow_ups.tenant_id and a.id=follow_ups.action_id
    and (private.can_access_hse(follow_ups.tenant_id,'hse.actions.read',a.site_id,false,'follow_up',follow_ups.id)
      or private.can_access_hse(follow_ups.tenant_id,'hse.actions.update_assigned',a.site_id,false,'follow_up',follow_ups.id))));
create policy followups_write on hse.follow_ups for all to authenticated
  using (exists (select 1 from hse.corrective_actions a where a.tenant_id=follow_ups.tenant_id and a.id=follow_ups.action_id
    and (private.can_access_hse(follow_ups.tenant_id,'hse.actions.manage',a.site_id,true,'follow_up',follow_ups.id)
      or private.can_access_hse(follow_ups.tenant_id,'hse.actions.update_assigned',a.site_id,true,'follow_up',follow_ups.id))))
  with check (exists (select 1 from hse.corrective_actions a where a.tenant_id=follow_ups.tenant_id and a.id=follow_ups.action_id
    and (private.can_access_hse(follow_ups.tenant_id,'hse.actions.manage',a.site_id,true,'follow_up',follow_ups.id)
      or private.can_access_hse(follow_ups.tenant_id,'hse.actions.update_assigned',a.site_id,true,'follow_up',follow_ups.id))));
create policy evidence_read on hse.evidence_files for select to authenticated using (
  private.can_access_hse(tenant_id,'hse.evidence.read',site_id,false,linked_record_type,linked_record_id) or private.can_access_hse(tenant_id,'hse.evidence.upload',site_id,false,linked_record_type,linked_record_id));
create policy evidence_insert on hse.evidence_files for insert to authenticated with check (uploaded_by=auth.uid() and private.can_access_hse(tenant_id,'hse.evidence.upload',site_id,true,linked_record_type,linked_record_id));
create policy evidence_update on hse.evidence_files for update to authenticated
  using (uploaded_by=auth.uid() and private.can_access_hse(tenant_id,'hse.evidence.upload',site_id,true,linked_record_type,linked_record_id))
  with check (uploaded_by=auth.uid() and private.can_access_hse(tenant_id,'hse.evidence.upload',site_id,true,linked_record_type,linked_record_id));
create policy audit_read on audit.events for select to authenticated using (
  private.is_platform_operator() or (tenant_id is not null and private.can_access_hse(tenant_id,'hse.audit.read')));

create or replace function private.audit_row_change() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_row jsonb; v_tenant_id uuid; v_record_id uuid;
begin
  v_row := to_jsonb(new);
  v_tenant_id := private.path_uuid(v_row->>'tenant_id');
  v_record_id := private.path_uuid(v_row->>'id');
  if v_record_id is null then v_record_id := private.path_uuid(v_row->>'site_id'); end if;
  insert into audit.events(tenant_id,actor_user_id,action_key,record_type,record_id,summary)
    values (v_tenant_id,auth.uid(),TG_TABLE_SCHEMA||'.'||TG_TABLE_NAME||'.'||lower(TG_OP),
      TG_TABLE_SCHEMA||'.'||TG_TABLE_NAME,v_record_id,jsonb_build_object('operation',TG_OP));
  return new;
end $$;
do $$ declare v_table text; begin
  foreach v_table in array array[
    'core.tenants','core.tenant_domains','core.tenant_entitlements','core.org_units','core.sites',
    'iam.memberships','iam.site_access','iam.member_permissions','iam.task_assignments',
    'hse.form_templates','hse.form_versions','hse.inspections','hse.inspection_reviews',
    'hse.findings','hse.corrective_actions','hse.action_updates','hse.follow_ups','hse.evidence_files'
  ] loop
    execute format('create trigger audit_row_change after insert or update on %s for each row execute function private.audit_row_change()',v_table);
  end loop;
end $$;

-- Private Storage bucket; object keys must be tenant UUID / site UUID / file name.
insert into storage.buckets(id,name,public) values ('sentriq-hse-evidence','sentriq-hse-evidence',false)
on conflict (id) do update set public=false;
create policy sentriq_evidence_read on storage.objects for select to authenticated using (
  bucket_id='sentriq-hse-evidence' and exists (
    select 1 from hse.evidence_files e where e.storage_key=storage.objects.name
      and e.tenant_id=private.path_uuid(split_part(storage.objects.name,'/',1))
      and e.site_id=private.path_uuid(split_part(storage.objects.name,'/',2))
      and (e.status='confirmed' or e.uploaded_by=auth.uid())
      and (private.can_access_hse(e.tenant_id,'hse.evidence.read',e.site_id,false,e.linked_record_type,e.linked_record_id)
        or private.can_access_hse(e.tenant_id,'hse.evidence.upload',e.site_id,false,e.linked_record_type,e.linked_record_id))));
create policy sentriq_evidence_upload on storage.objects for insert to authenticated with check (
  bucket_id='sentriq-hse-evidence' and exists (
    select 1 from hse.evidence_files e where e.storage_key=storage.objects.name and e.uploaded_by=auth.uid()
      and e.status='pending' and e.tenant_id=private.path_uuid(split_part(storage.objects.name,'/',1))
      and e.site_id=private.path_uuid(split_part(storage.objects.name,'/',2))
      and private.can_access_hse(e.tenant_id,'hse.evidence.upload',e.site_id,true,e.linked_record_type,e.linked_record_id)));

-- Read-only compatibility views for the current UI's workspace-oriented vocabulary.
create view api.v_workspaces with (security_invoker=true) as
  select id, id as "workspaceId", name, industry_label as "industryLabel", status, created_at as "createdAt"
  from core.tenants;
create view api.v_sites with (security_invoker=true) as
  select id, tenant_id as "workspaceId", name, code, city, status from core.sites;
create view api.v_memberships with (security_invoker=true) as
  select m.user_id as id, m.id as "membershipId", m.tenant_id as "workspaceId",
         m.display_name as "displayName", m.email, m.member_role as role,
         m.status, coalesce((select jsonb_agg(sa.site_id order by sa.site_id) from iam.site_access sa
           where sa.tenant_id=m.tenant_id and sa.membership_id=m.id and sa.active),'[]'::jsonb) as "siteIds"
  from iam.memberships m;
create view api.v_forms with (security_invoker=true) as
  select f.id, f.tenant_id as "workspaceId", f.title, f.category, f.status, f.revision,
         f.definition, f.owner_membership_id as "ownerMembershipId", f.updated_at as "updatedAt"
  from hse.form_templates f;
create view api.v_inspections with (security_invoker=true) as
  select i.id, i.tenant_id as "workspaceId", i.site_id as "siteId", i.template_id as "templateId",
         v.version as "templateVersion", i.title, m.user_id as "inspectorId", i.inspector_membership_id as "inspectorMembershipId",
         i.status, i.current_stage as "currentStage", i.answers, i.revision,
         i.created_at as "createdAt", i.submitted_at as "submittedAt", i.updated_at as "updatedAt"
  from hse.inspections i join hse.form_versions v on v.tenant_id=i.tenant_id and v.id=i.form_version_id
  left join iam.memberships m on m.tenant_id=i.tenant_id and m.id=i.inspector_membership_id;
create view api.v_inspection_reviews with (security_invoker=true) as
  select id,tenant_id as "workspaceId",inspection_id as "inspectionId",stage,decision,
         actor_user_id as "actorId",reason,revision,created_at as at
  from hse.inspection_reviews;
create view api.v_findings with (security_invoker=true) as
  select id, tenant_id as "workspaceId", site_id as "siteId", inspection_id as "inspectionId",
         question_id as "questionId", title, description, priority, status, created_at as "createdAt"
  from hse.findings;
create view api.v_actions with (security_invoker=true) as
  select a.id, a.tenant_id as "workspaceId", a.site_id as "siteId", a.finding_id as "findingId",
         a.inspection_id as "inspectionId", a.title, a.description, a.owner_membership_id as "ownerMembershipId",
         a.priority, a.status, a.response_due_at as "responseDueAt", a.plan_due_at as "planDueAt",
         a.closure_due_at as "closureDueAt", om.user_id as "ownerId", a.revision,
         a.created_at as "createdAt", a.updated_at as "updatedAt"
  from hse.corrective_actions a left join iam.memberships om on om.tenant_id=a.tenant_id and om.id=a.owner_membership_id;
create view api.v_follow_ups with (security_invoker=true) as
  select f.id, f.tenant_id as "workspaceId", f.action_id as "actionId", f.title,
         f.owner_membership_id as "ownerMembershipId", om.user_id as "ownerId", f.due_at as "dueAt", f.status, f.outcome
  from hse.follow_ups f left join iam.memberships om on om.tenant_id=f.tenant_id and om.id=f.owner_membership_id;
create view api.v_action_updates with (security_invoker=true) as
  select id,tenant_id as "workspaceId",action_id as "actionId",actor_user_id as "actorId",status,comment,created_at as at
  from hse.action_updates;
create view api.v_evidence with (security_invoker=true) as
  select id,tenant_id as "workspaceId",site_id as "siteId",file_name as "fileName",mime_type as "mimeType",
         size_bytes as "sizeBytes",status,linked_record_type as "linkedRecordType",linked_record_id as "linkedRecordId",
         uploaded_by as "uploadedBy",created_at as "createdAt",storage_key as "storageKey"
  from hse.evidence_files;
create view api.v_audit_events with (security_invoker=true) as
  select id,tenant_id as "workspaceId",actor_user_id as "actorId",action_key as action,
         record_type as "recordType",record_id as "recordId",summary as "summary",created_at as at
  from audit.events;

grant usage on schema core,iam,hse,audit,api to authenticated;
grant usage on schema private to authenticated;
grant select on api.v_workspaces,api.v_sites,api.v_memberships,api.v_forms,api.v_inspections,api.v_inspection_reviews,api.v_findings,api.v_actions,api.v_follow_ups,api.v_action_updates,api.v_evidence,api.v_audit_events to authenticated;
grant select on core.tenants,core.org_units,core.sites,core.tenant_domains,core.modules,core.tenant_entitlements,iam.memberships,iam.site_access,iam.permission_catalog,
  iam.member_permissions,iam.task_assignments,hse.form_templates,hse.form_versions,hse.inspections,
  hse.inspection_reviews,hse.findings,hse.corrective_actions,hse.action_updates,hse.follow_ups,
  hse.evidence_files,audit.events to authenticated;
grant insert,update on core.tenants,core.org_units,core.sites,core.tenant_domains,core.tenant_entitlements,iam.memberships,iam.site_access,iam.member_permissions,iam.task_assignments,
  hse.form_templates,hse.inspections,hse.findings,hse.corrective_actions,hse.follow_ups,hse.evidence_files to authenticated;
grant insert on hse.form_versions,hse.inspection_reviews,hse.evidence_files to authenticated;
revoke all on iam.platform_operators from public,anon,authenticated;
revoke all on function private.bootstrap_platform_owner(uuid),private.guard_membership_role_change(),private.guard_membership_identity(),private.guard_tenant_id_change(),private.guard_immutable_fields(),private.validate_evidence_link(),private.touch_updated_at(),private.audit_row_change(),private.guard_inspection_insert(),private.guard_inspection_update(),private.apply_inspection_review(),private.guard_action_update(),private.record_action_status() from public,anon,authenticated;
revoke all on function private.is_platform_operator(),private.is_platform_owner(),private.can_access_tenant(uuid),private.can_manage_tenant(uuid),private.can_access_core(uuid,text,uuid,boolean),private.can_access_hse(uuid,text,uuid,boolean,text,uuid),private.current_membership_id(uuid),private.can_review_hse(uuid,uuid,uuid,boolean) from public,anon;
grant execute on function private.is_platform_operator(),private.is_platform_owner(),private.can_access_tenant(uuid),private.can_manage_tenant(uuid),private.can_access_core(uuid,text,uuid,boolean),private.can_access_hse(uuid,text,uuid,boolean,text,uuid),private.current_membership_id(uuid),private.can_review_hse(uuid,uuid,uuid,boolean) to authenticated;
revoke all on function private.path_uuid(text) from public,anon;
grant execute on function private.path_uuid(text) to authenticated;
revoke all on function api.manage_subowner(uuid,boolean),api.create_tenant(text,text,uuid) from public,anon;
grant execute on function api.manage_subowner(uuid,boolean),api.create_tenant(text,text,uuid) to authenticated;

commit;
