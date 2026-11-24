-- Sub-owner authority model, per product owner decision (2026-11-24):
-- Owner and Sub-owner can do everything on the platform, except powers the
-- Owner explicitly withdrew from that Sub-owner. Previously a Sub-owner held
-- only explicitly granted keys (default: company.lifecycle).
--
-- Structural invariants kept owner-only (not withdrawable, they ARE the
-- owner's authority over the sub-owner relationship itself):
--   api.manage_subowner, api.set_subowner_platform_permission.
--
-- Close and rename move from owner-only hard gates to catalog-gated keys so
-- the Owner can withdraw them individually: company.close, company.rename.
-- Suspending a company_superadmin's membership moves from owner-only to the
-- existing membership.lifecycle key.

insert into iam.platform_permission_catalog(permission_key) values
 ('company.close'),
 ('company.rename')
on conflict(permission_key) do nothing;

-- Default-allow for subowners: an explicit granted=false row withdraws the
-- power; granted=true (or no row) allows it. Owner is unchanged (always allow).
create or replace function private.platform_permission_allowed(p_key text,p_actor uuid default null)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from iam.platform_operators o where o.user_id=coalesce(p_actor,private.request_actor_id()) and o.active
  and (o.operator_role='owner'
   or (o.operator_role='subowner' and not exists(select 1 from iam.platform_permission_grants g
        where g.user_id=o.user_id and g.permission_key=p_key and not g.granted))))
$$;

-- Company close: withdrawable via company.close instead of hard owner-only.
create or replace function api.platform_set_tenant_status(p_tenant_id uuid, p_status text, p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare v_previous text;
begin
 if not private.platform_permission_allowed('company.lifecycle') then raise exception 'platform_tenant_status_not_authorized' using errcode='42501';end if;
 if p_status is null or p_status not in ('active','suspended','closed') or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_tenant_status_invalid' using errcode='22023';end if;
 if p_status='closed' and not private.platform_permission_allowed('company.close') then raise exception 'company_close_not_allowed' using errcode='42501';end if;
 select status into v_previous from core.tenants where id=p_tenant_id for update;
 if not found or v_previous='closed' then raise exception 'active_or_suspended_company_required' using errcode='23514';end if;
 update core.tenants set status=p_status where id=p_tenant_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','platform.tenant.status_changed','core.tenants',p_tenant_id,
  jsonb_build_object('previous_status',v_previous,'status',p_status,'reason',btrim(p_reason)));
end $$;

-- Company rename: withdrawable via company.rename instead of hard owner-only.
create or replace function api.platform_rename_tenant(p_tenant_id uuid,p_name text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
begin
 if not private.platform_permission_allowed('company.rename') then raise exception 'company_rename_not_allowed' using errcode='42501';end if;
 if p_name is null or length(btrim(p_name)) not between 1 and 200 or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'company_rename_invalid' using errcode='22023';end if;
 update core.tenants set name=btrim(p_name) where id=p_tenant_id;
 if not found then raise exception 'company_not_found' using errcode='22023';end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','platform.tenant.renamed','core.tenants',p_tenant_id,jsonb_build_object('name',btrim(p_name),'reason',btrim(p_reason)));
end $$;

-- Superadmin membership lifecycle: withdrawable via membership.lifecycle.
CREATE OR REPLACE FUNCTION api.platform_set_membership_status(p_tenant_id uuid, p_membership_id uuid, p_status text, p_reason text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
 if not private.platform_permission_allowed('membership.lifecycle') and exists(select 1 from iam.memberships where tenant_id=p_tenant_id and id=p_membership_id and member_role='company_superadmin') then
  raise exception 'superadmin_lifecycle_not_allowed' using errcode='42501';end if;
 if not private.platform_permission_allowed('membership.lifecycle') or p_status not in ('active','suspended','ended')
  or p_reason is null or length(btrim(p_reason)) not between 3 and 500 then
  raise exception 'platform_membership_lifecycle_not_authorized' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-membership:'||p_tenant_id::text,0));
 update iam.memberships set status=p_status where tenant_id=p_tenant_id and id=p_membership_id;
 if not found then raise exception 'membership_not_found' using errcode='22023'; end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(p_tenant_id,private.request_actor_id(),'tenant','iam.platform.membership_status','iam.memberships',p_membership_id,
  jsonb_build_object('status',p_status,'reason',btrim(p_reason)));
end $function$;

-- Owner-only read: a sub-owner's effective platform powers (for the portal UI).
create or replace function api.platform_subowner_permissions(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare v_rows jsonb;
begin
 if not private.is_platform_owner() then raise exception 'only_owner_can_read_platform_permissions' using errcode='42501';end if;
 if not exists(select 1 from iam.platform_operators where user_id=p_user_id and operator_role='subowner') then
  raise exception 'subowner_not_found' using errcode='22023';end if;
 select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',private.platform_permission_allowed(c.permission_key,p_user_id),'explicit_row',g.granted) order by c.permission_key), '[]'::jsonb)
 into v_rows
 from iam.platform_permission_catalog c
 left join iam.platform_permission_grants g on g.user_id=p_user_id and g.permission_key=c.permission_key;
 return jsonb_build_object('rows',v_rows);
end $$;

revoke all on function api.platform_subowner_permissions(uuid) from public,anon,service_role;
grant execute on function api.platform_subowner_permissions(uuid) to authenticated;
