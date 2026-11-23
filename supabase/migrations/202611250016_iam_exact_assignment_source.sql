begin;
create or replace function api.assign_membership_role(
 p_tenant_id uuid,p_membership_id uuid,p_role_id uuid,p_role_version_id uuid,
 p_site_ids uuid[],p_org_unit_ids uuid[],p_starts_at timestamptz,p_ends_at timestamptz,p_reason text
) returns uuid language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=auth.uid(); v_role iam.roles%rowtype; v_target iam.memberships%rowtype;
        v_source uuid; v_actor_membership uuid; v_id uuid; v_site uuid; v_org uuid; v_has_tenant_scope boolean; v_expected_family text;
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
   if not exists(select 1 from core.sites s where s.tenant_id=p_tenant_id and s.id=v_site and s.status='active')
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
 select id into v_actor_membership from iam.memberships where tenant_id=p_tenant_id and user_id=v_actor and status='active';
 if not exists(select 1 from iam.memberships where id=v_actor_membership and member_role='company_superadmin') then
  select d.id into v_source from iam.delegation_envelopes d where d.tenant_id=p_tenant_id and d.delegate_membership_id=v_actor_membership
   and private.decision_source_valid(d.id,d.tenant_id) and 'role_assignment'=any(d.allowed_capabilities)
   and (d.level='tenant' or (d.level='employees_default' and v_target.member_role='employee')
    or (not v_has_tenant_scope and d.level='site' and cardinality(coalesce(p_site_ids,'{}'::uuid[]))>0
     and cardinality(coalesce(p_org_unit_ids,'{}'::uuid[]))=0 and not exists(select 1 from unnest(p_site_ids) x where x<>d.site_id))
    or (not v_has_tenant_scope and d.level='org_unit' and cardinality(coalesce(p_org_unit_ids,'{}'::uuid[]))>0
     and cardinality(coalesce(p_site_ids,'{}'::uuid[]))=0 and not exists(select 1 from unnest(p_org_unit_ids) x where x<>d.org_unit_id)))
   order by d.created_at desc,d.id limit 1;
  if v_source is null then raise exception 'one_exact_role_assignment_source_required' using errcode='42501';end if;
 end if;
 insert into iam.membership_roles(tenant_id,membership_id,role_id,role_version_id,starts_at,ends_at,granted_by,source_delegation_id)
 values(p_tenant_id,p_membership_id,p_role_id,p_role_version_id,p_starts_at,p_ends_at,v_actor,v_source) returning id into v_id;
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

commit;
