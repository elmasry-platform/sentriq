-- Forward-only security remediation. Preserve 001/002 and all customer rows.
begin;

-- Require an active tenant, enabled module, and active unrevoked grant or a
-- subscription/item whose status and half-open effective periods are current.
create or replace function private.has_module_entitlement(p_tenant_id uuid,p_module_key text)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from core.tenants t join core.modules m on m.enabled and m.module_key=p_module_key
   where t.id=p_tenant_id and t.status='active')
 and (
   exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.module_key=p_module_key
     and g.membership_id is null and g.status='active' and g.revoked_at is null
     and g.starts_at<=now() and now()<g.expires_at)
   or exists(select 1 from core.subscriptions s
     join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id
     where s.tenant_id=p_tenant_id and pe.module_key=p_module_key and s.status in ('active','trialing')
       and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
       and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
 );
$$;

-- Role permissions remain reusable normalized definitions. Scope is bound to
-- a membership's role assignment so the same role can safely serve different
-- sites/units without cloning its permissions.
alter table iam.membership_roles add constraint membership_roles_tenant_id_unique unique(tenant_id,id);
create table iam.membership_role_sites (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null,
 membership_role_id uuid not null,
 site_id uuid not null,
 granted_by uuid not null references auth.users(id) on delete restrict,
 granted_at timestamptz not null default now(),
 ends_at timestamptz,
 revoked_at timestamptz,
 revoked_by uuid references auth.users(id) on delete restrict,
 revoke_reason text,
 unique(tenant_id,membership_role_id,site_id),
 foreign key(tenant_id,membership_role_id) references iam.membership_roles(tenant_id,id) on delete restrict,
 foreign key(tenant_id,site_id) references core.sites(tenant_id,id) on delete restrict,
 check(ends_at is null or granted_at<ends_at),
 check((revoked_at is null and revoked_by is null and revoke_reason is null)
    or (revoked_at is not null and revoked_by is not null and length(btrim(revoke_reason))>=3))
);
create table iam.membership_role_org_units (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null,
 membership_role_id uuid not null,
 org_unit_id uuid not null,
 granted_by uuid not null references auth.users(id) on delete restrict,
 granted_at timestamptz not null default now(),
 ends_at timestamptz,
 revoked_at timestamptz,
 revoked_by uuid references auth.users(id) on delete restrict,
 revoke_reason text,
 unique(tenant_id,membership_role_id,org_unit_id),
 foreign key(tenant_id,membership_role_id) references iam.membership_roles(tenant_id,id) on delete restrict,
 foreign key(tenant_id,org_unit_id) references core.org_units(tenant_id,id) on delete restrict,
 check(ends_at is null or granted_at<ends_at),
 check((revoked_at is null and revoked_by is null and revoke_reason is null)
    or (revoked_at is not null and revoked_by is not null and length(btrim(revoke_reason))>=3))
);

create or replace function private.validate_membership_role_scope() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_assignment iam.membership_roles%rowtype; v_role uuid; v_scope text;
begin
 select * into v_assignment from iam.membership_roles mr
  where mr.tenant_id=new.tenant_id and mr.id=new.membership_role_id;
 if not found then raise exception 'role assignment not found in tenant' using errcode='23503'; end if;
 v_role:=v_assignment.role_id;
 v_scope:=case when tg_table_name='membership_role_sites' then 'site' else 'org_unit' end;
 if not exists(select 1 from iam.role_permissions rp where rp.role_id=v_role and rp.active and rp.scope_kind=v_scope) then
  raise exception 'role has no permission for this scope kind' using errcode='23514'; end if;
 return new;
end $$;
create trigger membership_role_site_scope_guard before insert or update on iam.membership_role_sites
 for each row execute function private.validate_membership_role_scope();
create trigger membership_role_org_scope_guard before insert or update on iam.membership_role_org_units
 for each row execute function private.validate_membership_role_scope();

create or replace function private.has_hse_permission(p_tenant_id uuid,p_membership_id uuid,p_permission text,
 p_site_id uuid,p_write boolean,p_task_kind text,p_task_id uuid)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(
   select 1 from (
     select rp.permission_key,rp.scope_kind,rp.can_read,rp.can_write,mr.id membership_role_id,
       null::uuid site_id,null::uuid org_unit_id,null::uuid task_id
     from iam.membership_roles mr join iam.roles r on r.id=mr.role_id
       join iam.role_permissions rp on rp.role_id=r.id and rp.active
     where mr.tenant_id=p_tenant_id and mr.membership_id=p_membership_id
       and mr.revoked_at is null and mr.starts_at<=now() and (mr.ends_at is null or now()<mr.ends_at)
       and r.active and (r.tenant_id is null or r.tenant_id=p_tenant_id)
     union all
     select g.permission_key,g.scope_kind,g.can_read,g.can_write,null::uuid membership_role_id,
       g.site_id,g.org_unit_id,g.task_id
     from iam.member_permissions g where g.tenant_id=p_tenant_id and g.membership_id=p_membership_id and g.active
   ) x
   left join core.sites s on s.tenant_id=p_tenant_id and s.id=p_site_id
   where x.permission_key=p_permission and (case when p_write then x.can_write else x.can_read end)
    and (p_site_id is null or exists(select 1 from iam.site_access sa where sa.tenant_id=p_tenant_id
         and sa.membership_id=p_membership_id and sa.site_id=p_site_id and sa.active))
    and (
      x.scope_kind='tenant'
      or (x.scope_kind='site' and (
          (x.membership_role_id is not null and exists(select 1 from iam.membership_role_sites rs
            where rs.tenant_id=p_tenant_id and rs.membership_role_id=x.membership_role_id and rs.site_id=p_site_id
              and rs.revoked_at is null and rs.granted_at<=now() and (rs.ends_at is null or now()<rs.ends_at)))
          or (x.membership_role_id is null and x.site_id=p_site_id)))
       or (x.scope_kind='org_unit' and exists(select 1 from iam.org_unit_access oa
          where oa.tenant_id=p_tenant_id and oa.membership_id=p_membership_id and oa.org_unit_id=s.org_unit_id and oa.active)
          and ((x.membership_role_id is not null and exists(select 1 from iam.membership_role_org_units ro
            where ro.tenant_id=p_tenant_id and ro.membership_role_id=x.membership_role_id and ro.org_unit_id=s.org_unit_id
              and ro.revoked_at is null and ro.granted_at<=now() and (ro.ends_at is null or now()<ro.ends_at)))
             or (x.membership_role_id is null and x.org_unit_id=s.org_unit_id)))
      or (x.scope_kind='assigned_task' and p_task_id is not null and (x.task_id is null or x.task_id=p_task_id)
          and exists(select 1 from iam.task_assignments ta where ta.tenant_id=p_tenant_id and ta.membership_id=p_membership_id
            and ta.task_kind=p_task_kind and ta.task_id=p_task_id and ta.active and ta.site_id=p_site_id
            and (ta.org_unit_id is null or ta.org_unit_id=s.org_unit_id)
            and (s.org_unit_id is null or exists(select 1 from iam.org_unit_access oa where oa.tenant_id=p_tenant_id
              and oa.membership_id=p_membership_id and oa.org_unit_id=s.org_unit_id and oa.active))))
    )
 );
$$;

-- Only platform operators can inspect commercial catalog or financial tables.
drop policy features_read on core.features;
create policy features_read on core.features for select to authenticated using(private.is_platform_operator());
drop policy plans_read on core.plans;
create policy plans_read on core.plans for select to authenticated using(private.is_platform_operator());
drop policy plan_entitlements_read on core.plan_entitlements;
create policy plan_entitlements_read on core.plan_entitlements for select to authenticated using(private.is_platform_operator());
create or replace function api.list_my_entitlements(p_tenant_id uuid)
returns table(entitlement_kind text,entitlement_key text,entitled boolean)
language plpgsql stable security definer set search_path='' as $$
declare v_membership uuid;
begin
 select m.id into v_membership from iam.memberships m join core.tenants t on t.id=m.tenant_id
  where m.tenant_id=p_tenant_id and m.user_id=auth.uid() and m.member_role='company_superadmin'
    and m.status='active' and t.status='active';
 if v_membership is null then raise exception 'active_company_superadmin_required' using errcode='42501'; end if;
 return query select 'module'::text,m.module_key,private.has_module_entitlement(p_tenant_id,m.module_key) from core.modules m;
 return query select 'feature'::text,f.feature_key,private.has_feature_entitlement(p_tenant_id,v_membership,f.feature_key) from core.features f;
end $$;

-- Expire stale pending invites in the same transaction before inserting a new
-- invite. No volatile now() expression is used in the unique index predicate.
create or replace function api.create_invitation(p_tenant_id uuid,p_email text,p_level text,p_actor_user_id uuid,p_ttl interval default interval '7 days')
returns table(invitation_id uuid,token text) language plpgsql security definer set search_path='' as $$
declare v_token text:=encode(extensions.gen_random_bytes(32),'hex'); v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if not exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id where m.tenant_id=p_tenant_id
      and m.user_id=p_actor_user_id and m.member_role='company_superadmin' and m.status='active' and t.status='active')
   or p_level not in ('company_admin','employee') or v_email is null or length(v_email)<3 or length(v_email)>254
   or p_ttl is null or p_ttl<=interval '0' or p_ttl>interval '30 days' then raise exception 'invitation_not_allowed' using errcode='42501'; end if;
 update iam.invitations set revoked_at=now(),revoked_by=p_actor_user_id,
   revoke_reason='Expired before reinvitation'
  where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null and expires_at<=now();
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),p_level,p_actor_user_id,now()+p_ttl)
 returning id into v_id;
 return query select v_id,v_token;
end $$;

-- Role assignments and their normalized scope bindings are company-admin data.
do $$ declare t text; begin
 foreach t in array array['iam.membership_role_sites','iam.membership_role_org_units'] loop
  execute format('alter table %s enable row level security',t);
  execute format('alter table %s force row level security',t);
 end loop;
end $$;
create policy membership_role_sites_read on iam.membership_role_sites for select to authenticated
 using(private.can_manage_tenant(tenant_id) or exists(select 1 from iam.membership_roles mr
   where mr.tenant_id=membership_role_sites.tenant_id and mr.id=membership_role_sites.membership_role_id
     and mr.membership_id=private.current_membership_id(tenant_id)));
create policy membership_role_sites_insert on iam.membership_role_sites for insert to authenticated
 with check(private.can_manage_tenant(tenant_id) and granted_by=auth.uid());
create policy membership_role_sites_update on iam.membership_role_sites for update to authenticated
 using(private.can_manage_tenant(tenant_id)) with check(private.can_manage_tenant(tenant_id));
create policy membership_role_org_units_read on iam.membership_role_org_units for select to authenticated
 using(private.can_manage_tenant(tenant_id) or exists(select 1 from iam.membership_roles mr
   where mr.tenant_id=membership_role_org_units.tenant_id and mr.id=membership_role_org_units.membership_role_id
     and mr.membership_id=private.current_membership_id(tenant_id)));
create policy membership_role_org_units_insert on iam.membership_role_org_units for insert to authenticated
 with check(private.can_manage_tenant(tenant_id) and granted_by=auth.uid());
create policy membership_role_org_units_update on iam.membership_role_org_units for update to authenticated
 using(private.can_manage_tenant(tenant_id)) with check(private.can_manage_tenant(tenant_id));
grant select,insert,update on iam.membership_role_sites,iam.membership_role_org_units to authenticated;
revoke delete on iam.membership_role_sites,iam.membership_role_org_units from authenticated,anon;
revoke all on function private.validate_membership_role_scope() from public,anon,authenticated;
revoke all on function private.has_hse_permission(uuid,uuid,text,uuid,boolean,text,uuid) from public,anon,authenticated;
revoke all on function api.create_invitation(uuid,text,text,uuid,interval) from public,anon,authenticated;
grant execute on function api.create_invitation(uuid,text,text,uuid,interval) to service_role;
revoke all on function api.list_my_entitlements(uuid) from public,anon,authenticated;
grant execute on function api.list_my_entitlements(uuid) to authenticated;
revoke all on function private.has_module_entitlement(uuid,text) from public,anon,authenticated;
revoke all on function private.is_platform_operator() from public,anon;
grant execute on function private.is_platform_operator() to authenticated;

-- Preserve actor/scope/record identity and allowlisted diffs for role-scope
-- lifecycle changes, without copying arbitrary text/token payloads.
create or replace function private.audit_row_change() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_old jsonb; v_new jsonb; v_row jsonb; v_tenant uuid; v_id uuid; v_diff jsonb;
begin
 v_old:=case when tg_op in ('UPDATE','DELETE') then to_jsonb(old) else '{}'::jsonb end;
 v_new:=case when tg_op in ('INSERT','UPDATE') then to_jsonb(new) else '{}'::jsonb end;
 v_row:=case when tg_op='DELETE' then v_old else v_new end;
 v_tenant:=private.path_uuid(v_row->>'tenant_id');
 if v_tenant is null and v_row ? 'role_id' then select tenant_id into v_tenant from iam.roles where id=private.path_uuid(v_row->>'role_id'); end if;
 v_id:=private.path_uuid(v_row->>'id');
 if v_id is null then v_id:=private.path_uuid(v_row->>'site_id'); end if;
 if v_id is null then v_id:=private.path_uuid(v_row->>'role_id'); end if;
 select coalesce(jsonb_object_agg(k,jsonb_build_object('before',v_old->k,'after',v_new->k)),'{}'::jsonb) into v_diff
 from unnest(array['name','status','member_role','membership_id','membership_role_id','granted_by','assigned_by','module_key','feature_key','permission_key','scope_kind','site_id','org_unit_id','task_id','role_id','role_key','label','starts_at','ends_at','expires_at','revoked_at','revoked_by','active','enabled','can_read','can_write','title','category','revision','current_stage','decision','priority','owner_membership_id','due_at','outcome','linked_record_type','size_bytes','billing_treatment','bill_to_tenant_id','quantity','price_minor','unit_price_minor','currency','invoice_number','subtotal_minor','tax_minor','total_minor','period_start','period_end','canceled_at']) k
 where v_old->k is distinct from v_new->k and (v_old ? k or v_new ? k);
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,request_id,action_key,record_type,record_id,summary)
 values(v_tenant,auth.uid(),case when v_tenant is not null then private.current_membership_id(v_tenant) end,
   case when v_tenant is null then 'platform' else 'tenant' end,nullif(current_setting('request.headers',true)::jsonb->>'x-request-id',''),
   tg_table_schema||'.'||tg_table_name||'.'||lower(tg_op),tg_table_schema||'.'||tg_table_name,v_id,
   jsonb_build_object('operation',tg_op,'changed_fields',v_diff));
 if tg_op='DELETE' then return old; end if; return new;
end $$;
revoke all on function private.audit_row_change() from public,anon,authenticated;

-- Complete audit coverage for the new role-scope bindings.
drop trigger if exists audit_row_change on core.modules;
create trigger audit_row_change after insert or update or delete on core.modules
 for each row execute function private.audit_row_change();
do $$ declare t text; begin
 foreach t in array array['iam.membership_role_sites','iam.membership_role_org_units'] loop
  execute format('create trigger audit_row_change after insert or update or delete on %s for each row execute function private.audit_row_change()',t);
 end loop;
end $$;

commit;
