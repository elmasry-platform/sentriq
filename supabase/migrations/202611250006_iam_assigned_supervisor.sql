-- Assignment-limited supervisor projection. Base People/Engagement table access
-- is not widened. Notes live separately and cannot edit identity/job/site data.
begin;
insert into iam.permission_catalog(permission_key,module_key,label,supported_actions,supported_scope_kinds)
values('hse.people.assigned','hse','Assigned engagement supervisor',array['read','notes'],array['site','org_unit','assigned_task']);
create table iam.engagement_supervisors (
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null,membership_id uuid not null,engagement_id uuid not null,
 starts_at timestamptz not null default now(),ends_at timestamptz,status text not null default 'active' check(status in ('active','revoked')),
 created_by uuid not null references auth.users(id),reason text not null check(length(btrim(reason)) between 3 and 500),
 foreign key(tenant_id,membership_id) references iam.memberships(tenant_id,id),
 foreign key(tenant_id,engagement_id) references hse.person_engagements(tenant_id,id),
 check(ends_at is null or starts_at<ends_at),unique(tenant_id,id)
);
create unique index engagement_supervisor_live_unique on iam.engagement_supervisors(tenant_id,membership_id,engagement_id) where status='active';
create table hse.engagement_supervisor_notes (
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null,engagement_id uuid not null,
 author_membership_id uuid not null,note text not null check(length(btrim(note)) between 1 and 2000),created_at timestamptz not null default now(),
 foreign key(tenant_id,engagement_id) references hse.person_engagements(tenant_id,id),
 foreign key(tenant_id,author_membership_id) references iam.memberships(tenant_id,id),unique(tenant_id,id)
);
alter table iam.engagement_supervisors enable row level security;
alter table iam.engagement_supervisors force row level security;
alter table hse.engagement_supervisor_notes enable row level security;
alter table hse.engagement_supervisor_notes force row level security;
revoke all on iam.engagement_supervisors,hse.engagement_supervisor_notes from public,anon,authenticated,service_role;

create or replace function private.supervisor_context_allowed(p_tenant uuid,p_engagement uuid,p_action text)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from hse.person_engagements e
  join iam.memberships m on m.tenant_id=e.tenant_id and m.user_id=private.request_actor_id() and m.status='active'
  join core.tenants t on t.id=e.tenant_id and t.status='active'
  join iam.engagement_supervisors s on s.tenant_id=e.tenant_id and s.engagement_id=e.id and s.membership_id=m.id
  where e.tenant_id=p_tenant and e.id=p_engagement and e.status='active'
   and s.status='active' and s.starts_at<=now() and (s.ends_at is null or now()<s.ends_at)
   and private.people_scope_allowed(p_tenant,m.id,e.site_id,e.org_unit_id)
   and api.authorize(p_tenant,'hse.people.assigned',p_action,e.site_id,e.org_unit_id))
$$;
create or replace function api.assigned_engagement(p_tenant_id uuid,p_engagement_id uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare result jsonb;
begin
 if not private.supervisor_context_allowed(p_tenant_id,p_engagement_id,'read') then
  raise exception 'assigned_engagement_not_authorized' using errcode='42501'; end if;
 select jsonb_build_object('identity',jsonb_build_object('person_id',p.id,'display_name',p.display_name),
  'worker_ref',jsonb_build_object('worker_number',p.worker_number,'external_worker_reference',e.external_worker_reference),
  'engagement',jsonb_build_object('id',e.id,'engagement_type',e.engagement_type,'status',e.status,'starts_at',e.starts_at,'ends_at',e.ends_at),
  'assignment',jsonb_build_object('access','assigned_read','write','notes_only'),
  'job',jsonb_build_object('job_title_snapshot',e.job_title_snapshot),
  'organization',jsonb_build_object('site_id',e.site_id,'org_unit_id',e.org_unit_id,'contractor_organization_id',e.contractor_organization_id),
  'work_contact',jsonb_build_object()) into result
 from hse.person_engagements e join hse.people p on p.tenant_id=e.tenant_id and p.id=e.person_id
 where e.tenant_id=p_tenant_id and e.id=p_engagement_id;
 return result;
end $$;
create or replace function api.add_engagement_note(p_tenant_id uuid,p_engagement_id uuid,p_note text)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid;v_membership uuid;
begin
 if not private.supervisor_context_allowed(p_tenant_id,p_engagement_id,'notes')
  or p_note is null or length(btrim(p_note)) not between 1 and 2000 then
  raise exception 'assigned_engagement_notes_not_authorized' using errcode='42501'; end if;
 select id into v_membership from iam.memberships where tenant_id=p_tenant_id and user_id=private.request_actor_id() and status='active';
 insert into hse.engagement_supervisor_notes(tenant_id,engagement_id,author_membership_id,note)
 values(p_tenant_id,p_engagement_id,v_membership,btrim(p_note)) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),v_membership,'assigned_task','hse.engagement.note_added','hse.engagement_supervisor_notes',v_id,
  jsonb_build_object('engagement_id',p_engagement_id));
 return v_id;
end $$;
create or replace function api.assign_engagement_supervisor(p_tenant_id uuid,p_engagement_id uuid,p_membership_id uuid,p_ends_at timestamptz,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare e hse.person_engagements%rowtype;v_id uuid;
begin
 select * into e from hse.person_engagements where tenant_id=p_tenant_id and id=p_engagement_id and status='active' for key share;
 if not found or not private.phase1_can_manage(p_tenant_id,'scope_management',p_membership_id,e.site_id,e.org_unit_id)
  or not api.authorize(p_tenant_id,'hse.people.assigned','read',e.site_id,e.org_unit_id)
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500
  or (p_ends_at is not null and p_ends_at<=now())
  or not exists(select 1 from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and status='active') then
  raise exception 'supervisor_assignment_not_authorized' using errcode='42501'; end if;
 insert into iam.engagement_supervisors(tenant_id,membership_id,engagement_id,ends_at,created_by,reason)
 values(p_tenant_id,p_membership_id,p_engagement_id,p_ends_at,private.request_actor_id(),btrim(p_reason)) returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'assigned_task','iam.engagement_supervisor.assigned','iam.engagement_supervisors',v_id,
  jsonb_build_object('engagement_id',p_engagement_id,'membership_id',p_membership_id,'reason',btrim(p_reason)));
 return v_id;
end $$;
create trigger supervisor_tenant_immutable before update of tenant_id on iam.engagement_supervisors
 for each row execute function private.guard_tenant_id_immutable();
create trigger supervisor_notes_immutable before update or delete on hse.engagement_supervisor_notes
 for each row execute function private.reject_person_engagement_event_mutation();
revoke all on function private.supervisor_context_allowed(uuid,uuid,text),api.assigned_engagement(uuid,uuid),api.add_engagement_note(uuid,uuid,text),
 api.assign_engagement_supervisor(uuid,uuid,uuid,timestamptz,text) from public,anon,authenticated,service_role;
grant execute on function api.assigned_engagement(uuid,uuid),api.add_engagement_note(uuid,uuid,text),
 api.assign_engagement_supervisor(uuid,uuid,uuid,timestamptz,text) to authenticated;
commit;
