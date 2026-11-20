-- SENTRIQ database stabilization. Forward-only corrections for the unmerged
-- feature branch; preserve existing rows and immutable history.
begin;

-- Retired plans cannot continue authorizing a subscription. A suspended or
-- past-due subscription is not effective and does not reserve a tenant's live
-- subscription slot; active/trialing are the only effective/live statuses.
create or replace function private.has_module_entitlement(p_tenant_id uuid,p_module_key text)
returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from core.tenants t join core.modules m on m.module_key=p_module_key and m.enabled
   where t.id=p_tenant_id and t.status='active')
 and (
   exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.module_key=p_module_key
     and g.membership_id is null and g.status='active' and g.revoked_at is null
     and g.starts_at<=now() and now()<g.expires_at)
   or exists(select 1 from core.subscriptions s
     join core.plans p on p.id=s.plan_id and p.status='active'
     join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
     where s.tenant_id=p_tenant_id and pe.module_key=p_module_key and s.status in ('active','trialing')
       and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
       and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
 );
$$;

create or replace function private.has_feature_entitlement(p_tenant_id uuid,p_membership_id uuid,p_feature_key text)
returns boolean language sql stable security definer set search_path='' as $$
 select f.enabled and private.has_module_entitlement(p_tenant_id,f.module_key)
   and exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
     where m.tenant_id=p_tenant_id and m.id=p_membership_id and m.status='active' and t.status='active')
   and (
     exists(select 1 from core.subscriptions s
       join core.plans p on p.id=s.plan_id and p.status='active'
       join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
       join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
       where s.tenant_id=p_tenant_id and pe.feature_key=p_feature_key and s.status in ('active','trialing')
         and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
         and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at))
     or exists(select 1 from core.entitlement_grants g where g.tenant_id=p_tenant_id and g.feature_key=p_feature_key
       and (g.membership_id is null or g.membership_id=p_membership_id) and g.status='active' and g.revoked_at is null
       and g.starts_at<=now() and now()<g.expires_at
       and (g.billing_treatment<>'tenant_billable' or g.bill_to_tenant_id=p_tenant_id))
   )
 from core.features f where f.feature_key=p_feature_key;
$$;

-- Idempotency keys identify one usage request globally. The two-column index
-- remains useful for tenant queries, while this unique index prevents the same
-- key from being replayed against a different tenant.
create unique index usage_events_idempotency_key_global on core.usage_events(idempotency_key);

create or replace function api.record_feature_usage(
 p_tenant_id uuid,p_membership_id uuid,p_feature_key text,p_idempotency_key text,
 p_quantity numeric,p_usage_unit text,p_metadata jsonb default '{}'::jsonb)
returns uuid language plpgsql security definer set search_path='' as $$
declare
 v_id uuid; v_existing core.usage_events%rowtype; v_grant core.entitlement_grants%rowtype;
 v_grant_id uuid; v_subscription_id uuid; v_cap numeric; v_used numeric;
 v_rate bigint; v_ccy char(3); v_treatment text:='tenant_billable';
 v_period_start timestamptz; v_period_end timestamptz;
begin
 if auth.role()<>'service_role' or p_tenant_id is null or p_membership_id is null or p_feature_key is null
   or p_quantity is null or p_quantity<=0 or p_idempotency_key is null
   or length(p_idempotency_key) not between 8 and 200 or p_usage_unit is null
   or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb))<>'object'
   or coalesce(p_metadata,'{}'::jsonb) ?| array['prompt','response','completion','token_text','secret','authorization'] then
   raise exception 'trusted_usage_recording_required' using errcode='42501';
 end if;
 -- Lock and replay the key before entitlement/quota checks. Exact retries are
 -- reads of the original immutable event, including after quota exhaustion or
 -- grant expiry. Billing configuration remains the original event snapshot.
 perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-key:'||p_idempotency_key,0));
 select * into v_existing from core.usage_events where idempotency_key=p_idempotency_key for update;
 if found then
   if v_existing.tenant_id is distinct from p_tenant_id
     or v_existing.beneficiary_membership_id is distinct from p_membership_id
     or v_existing.feature_key is distinct from p_feature_key
     or v_existing.usage_unit is distinct from p_usage_unit
     or v_existing.quantity is distinct from p_quantity
     or v_existing.metadata is distinct from coalesce(p_metadata,'{}'::jsonb) then
     raise exception 'idempotency_key_payload_conflict' using errcode='23505';
   end if;
   return v_existing.id;
 end if;

 if not exists(select 1 from core.features f where f.feature_key=p_feature_key and f.usage_unit=p_usage_unit) then
   raise exception 'usage_unit_or_feature_invalid' using errcode='22023';
 end if;

 if not private.has_feature_entitlement(p_tenant_id,p_membership_id,p_feature_key) then
   raise exception 'feature_not_entitled' using errcode='42501';
 end if;

 select * into v_grant from core.entitlement_grants g
  where g.tenant_id=p_tenant_id and g.feature_key=p_feature_key
    and (g.membership_id=p_membership_id or g.membership_id is null)
    and g.status='active' and g.revoked_at is null and g.starts_at<=now() and now()<g.expires_at
  order by (g.membership_id is not null) desc,g.starts_at desc,g.id
  limit 1 for share;
 if found then
   v_grant_id:=v_grant.id; v_cap:=v_grant.quota; v_treatment:=v_grant.billing_treatment;
   v_rate:=v_grant.unit_price_minor; v_ccy:=v_grant.currency;
 else
   select s.id,pe.quota,pe.usage_rate_minor,pe.usage_currency,s.current_period_start,s.current_period_end
     into v_subscription_id,v_cap,v_rate,v_ccy,v_period_start,v_period_end
   from core.subscriptions s join core.plans p on p.id=s.plan_id and p.status='active'
     join core.subscription_items si on si.tenant_id=s.tenant_id and si.subscription_id=s.id
     join core.plan_entitlements pe on pe.id=si.plan_entitlement_id and pe.plan_id=s.plan_id
   where s.tenant_id=p_tenant_id and pe.feature_key=p_feature_key and s.status in ('active','trialing')
     and s.starts_at<=now() and s.current_period_start<=now() and now()<s.current_period_end
     and si.starts_at<=now() and (si.ends_at is null or now()<si.ends_at)
   limit 1 for share of s,si;
   if v_subscription_id is null then raise exception 'feature_not_entitled' using errcode='42501'; end if;
 end if;

 if v_cap is not null then
   if v_grant_id is not null then
     perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-quota-grant:'||v_grant_id::text,0));
     select coalesce(sum(quantity),0) into v_used from core.usage_events where grant_id=v_grant_id;
   else
     perform pg_advisory_xact_lock(hashtextextended('sentriq-usage-quota-sub:'||p_tenant_id::text||':'||p_feature_key||':'||v_period_start::text,0));
     select coalesce(sum(quantity),0) into v_used from core.usage_events
       where tenant_id=p_tenant_id and feature_key=p_feature_key and grant_id is null
         and occurred_at>=v_period_start and occurred_at<v_period_end;
   end if;
   if v_used+p_quantity>v_cap then raise exception 'grant_usage_quota_exceeded' using errcode='54000'; end if;
 end if;

 insert into core.usage_events(tenant_id,beneficiary_membership_id,feature_key,grant_id,payer_tenant_id,
   billing_treatment,idempotency_key,usage_unit,quantity,unit_price_minor,currency,metadata)
 values(p_tenant_id,p_membership_id,p_feature_key,v_grant_id,
   case when v_treatment='tenant_billable' then p_tenant_id end,v_treatment,p_idempotency_key,p_usage_unit,
   p_quantity,v_rate,v_ccy,coalesce(p_metadata,'{}'::jsonb))
 on conflict do nothing returning id into v_id;
 if v_id is null then
   select * into v_existing from core.usage_events where idempotency_key=p_idempotency_key;
   if v_existing.tenant_id is distinct from p_tenant_id
     or v_existing.beneficiary_membership_id is distinct from p_membership_id
     or v_existing.feature_key is distinct from p_feature_key
     or v_existing.usage_unit is distinct from p_usage_unit
     or v_existing.quantity is distinct from p_quantity
     or v_existing.metadata is distinct from coalesce(p_metadata,'{}'::jsonb) then
     raise exception 'idempotency_key_payload_conflict' using errcode='23505';
   end if;
   return v_existing.id;
 end if;
 return v_id;
end $$;

create or replace function api.invoice_usage_event(p_usage_event_id uuid,p_invoice_id uuid,p_description text)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_usage core.usage_events%rowtype; v_invoice core.invoices%rowtype;
 v_item uuid; v_existing_invoice uuid; v_amount bigint;
begin
 if auth.role()<>'service_role' or p_usage_event_id is null or p_invoice_id is null
   or p_description is null or length(btrim(p_description)) not between 1 and 300 then
   raise exception 'trusted_billing_required' using errcode='42501';
 end if;
 select * into v_usage from core.usage_events where id=p_usage_event_id for update;
 if not found then raise exception 'usage_event_not_found' using errcode='22023'; end if;
 select * into v_invoice from core.invoices where id=p_invoice_id for update;
 if not found then raise exception 'invoice_not_found' using errcode='22023'; end if;

 -- Idempotent retries return their original line even after the invoice has
 -- moved out of draft. A usage event cannot be reassigned to another invoice.
 select id,invoice_id into v_item,v_existing_invoice from core.invoice_items
   where usage_event_id=v_usage.id for update;
 if found then
   if v_existing_invoice is distinct from p_invoice_id then
     raise exception 'usage_event_already_invoiced' using errcode='23505';
   end if;
   return v_item;
 end if;

 if v_usage.billing_treatment<>'tenant_billable' or v_usage.payer_tenant_id is null
   or v_usage.tenant_id<>v_usage.payer_tenant_id or v_invoice.tenant_id<>v_usage.payer_tenant_id
   or v_invoice.status<>'draft' or v_usage.unit_price_minor is null or v_usage.currency is null
   or v_invoice.currency<>v_usage.currency or v_usage.occurred_at<v_invoice.period_start
   or v_usage.occurred_at>=v_invoice.period_end then
   raise exception 'usage_event_not_invoiceable' using errcode='22023';
 end if;
 v_amount:=ceil(v_usage.quantity*v_usage.unit_price_minor)::bigint;
 insert into core.invoice_items(tenant_id,invoice_id,usage_event_id,description,service_period_start,
   service_period_end,quantity,unit_price_minor,amount_minor,currency)
 values(v_invoice.tenant_id,v_invoice.id,v_usage.id,p_description,v_usage.occurred_at,
   v_usage.occurred_at+interval '1 microsecond',v_usage.quantity,v_usage.unit_price_minor,
   v_amount,v_usage.currency)
 on conflict(usage_event_id) where usage_event_id is not null do nothing returning id into v_item;
 if v_item is null then
   select id,invoice_id into v_item,v_existing_invoice from core.invoice_items where usage_event_id=v_usage.id;
   if v_existing_invoice is distinct from p_invoice_id then
     raise exception 'usage_event_already_invoiced' using errcode='23505';
   end if;
 else
   update core.invoices set subtotal_minor=subtotal_minor+v_amount,total_minor=total_minor+v_amount where id=v_invoice.id;
 end if;
 return v_item;
end $$;

-- Past-due/suspended records deny access but do not hold the unique live slot.
drop index core.one_live_subscription_per_tenant;
create unique index one_live_subscription_per_tenant on core.subscriptions(tenant_id)
 where status in ('trialing','active');

create or replace function api.update_subscription_status(p_subscription_id uuid,p_status text) returns void
language plpgsql security definer set search_path='' as $$
declare v_sub core.subscriptions%rowtype; v_allowed boolean;
begin
 if not private.is_platform_operator() or p_status not in ('trialing','active','past_due','suspended','canceled','expired') then
   raise exception 'subscription_update_not_allowed' using errcode='42501';
 end if;
 select * into v_sub from core.subscriptions where id=p_subscription_id for update;
 if not found then raise exception 'subscription_not_found_or_final' using errcode='22023'; end if;
 if p_status=v_sub.status then return; end if;
 v_allowed:=case v_sub.status
   when 'trialing' then p_status in ('active','past_due','suspended','canceled','expired')
   when 'active' then p_status in ('past_due','suspended','canceled','expired')
   when 'past_due' then p_status in ('active','suspended','canceled','expired')
   when 'suspended' then p_status in ('active','past_due','canceled','expired')
   else false
 end;
 if not v_allowed then raise exception 'subscription_transition_not_allowed' using errcode='23514'; end if;
 if p_status in ('active','trialing') and
    (v_sub.starts_at>now() or v_sub.current_period_start>now() or v_sub.current_period_end<=now()
     or not exists(select 1 from core.plans p where p.id=v_sub.plan_id and p.status='active')) then
   raise exception 'subscription_period_or_plan_not_effective' using errcode='23514';
 end if;
 update core.subscriptions set status=p_status,
   canceled_at=case when p_status='canceled' then coalesce(canceled_at,now()) else null end
 where id=v_sub.id;
end $$;

create or replace function api.create_subscription(p_tenant_id uuid,p_plan_id uuid,p_starts_at timestamptz,
 p_period_end timestamptz,p_currency char(3),p_items jsonb) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_sub uuid; v_item jsonb;
begin
 if not private.is_platform_operator() or p_tenant_id is null or p_plan_id is null
   or p_starts_at is null or p_period_end is null or p_starts_at>=p_period_end
   or p_currency is null or jsonb_typeof(p_items)<>'array' or jsonb_array_length(p_items)=0 then
   raise exception 'subscription_not_allowed' using errcode='42501';
 end if;
 if not exists(select 1 from core.plans p where p.id=p_plan_id and p.status='active' and p.currency=p_currency) then
   raise exception 'plan_unavailable_or_currency_mismatch' using errcode='22023';
 end if;
 insert into core.subscriptions(tenant_id,plan_id,status,starts_at,current_period_start,current_period_end,created_by)
 values(p_tenant_id,p_plan_id,'active',p_starts_at,p_starts_at,p_period_end,auth.uid()) returning id into v_sub;
 for v_item in select value from jsonb_array_elements(p_items) loop
   if not exists(select 1 from core.plan_entitlements pe where pe.id=(v_item->>'plan_entitlement_id')::uuid and pe.plan_id=p_plan_id) then
     raise exception 'subscription_item_not_in_plan' using errcode='22023';
   end if;
   insert into core.subscription_items(tenant_id,subscription_id,plan_entitlement_id,quantity,
     unit_price_minor,currency,starts_at,ends_at)
   values(p_tenant_id,v_sub,(v_item->>'plan_entitlement_id')::uuid,
     coalesce((v_item->>'quantity')::numeric,1),(v_item->>'unit_price_minor')::bigint,
     p_currency,p_starts_at,p_period_end);
 end loop;
 if (select count(*) from core.subscription_items where subscription_id=v_sub)<>
    (select count(*) from core.plan_entitlements where plan_id=p_plan_id) then
   raise exception 'subscription_requires_all_plan_entitlements' using errcode='22023';
 end if;
 return v_sub;
end $$;

create or replace function api.issue_entitlement_grant(p_tenant_id uuid,p_module_key text,p_feature_key text,
 p_membership_id uuid,p_starts_at timestamptz,p_expires_at timestamptz,p_reason text,p_billing_treatment text,
 p_currency char(3),p_unit_price_minor bigint,p_quota numeric default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid;
begin
 if not private.is_platform_operator() or p_starts_at is null or p_expires_at is null or p_starts_at>=p_expires_at
   or ((p_module_key is not null)::integer+(p_feature_key is not null)::integer<>1)
   or p_billing_treatment not in ('tenant_billable','complimentary','platform_absorbed')
   or (p_unit_price_minor is not null and p_currency is null)
   or (p_currency is not null and p_currency::text !~ '^[A-Z]{3}$') then
   raise exception 'grant_not_allowed' using errcode='42501';
 end if;
 if p_membership_id is not null and not exists(select 1 from iam.memberships
    where tenant_id=p_tenant_id and id=p_membership_id) then
   raise exception 'grant_membership_mismatch' using errcode='23503';
 end if;
 if p_module_key is not null and not exists(select 1 from core.modules where module_key=p_module_key) then
   raise exception 'module_disabled_or_unknown' using errcode='22023';
 end if;
 if p_feature_key is not null and not exists(select 1 from core.features where feature_key=p_feature_key and enabled) then
   raise exception 'feature_disabled_or_unknown' using errcode='22023';
 end if;
 insert into core.entitlement_grants(tenant_id,module_key,feature_key,membership_id,starts_at,expires_at,
   granted_by,reason,billing_treatment,bill_to_tenant_id,currency,unit_price_minor,quota)
 values(p_tenant_id,p_module_key,p_feature_key,p_membership_id,p_starts_at,p_expires_at,auth.uid(),p_reason,
   p_billing_treatment,case when p_billing_treatment='tenant_billable' then p_tenant_id end,
   p_currency,p_unit_price_minor,p_quota) returning id into v_id;
 return v_id;
end $$;

create or replace function api.set_entitlement_grant_status(p_grant_id uuid,p_status text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare v_tenant uuid; v_old_status text;
begin
 if not private.is_platform_operator() or p_status not in ('active','suspended')
   or length(btrim(coalesce(p_reason,'')))<3 then
   raise exception 'grant_status_update_not_allowed' using errcode='42501';
 end if;
 select tenant_id,status into v_tenant,v_old_status from core.entitlement_grants
   where id=p_grant_id and revoked_at is null for update;
 if not found then raise exception 'grant_not_found_or_revoked' using errcode='22023'; end if;
 if v_old_status=p_status then return; end if;
 update core.entitlement_grants set status=p_status where id=p_grant_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(null,auth.uid(),'platform','core.entitlement_grants.status_changed','core.entitlement_grants',p_grant_id,
   jsonb_build_object('tenant_id',v_tenant,'before_status',v_old_status,'after_status',p_status,'reason',p_reason));
end $$;

-- Owner-only Subowner lifecycle with truthful/idempotent audit transitions.
create or replace function api.manage_subowner(p_user_id uuid,p_active boolean) returns void
language plpgsql security definer set search_path='' as $$
declare v_role text; v_active boolean; v_action text;
begin
 if not private.is_platform_owner() or p_user_id is null or p_active is null then
   raise exception 'subowner_management_not_allowed' using errcode='42501';
 end if;
 if not exists(select 1 from auth.users where id=p_user_id) then
   raise exception 'subowner_user_not_found' using errcode='22023';
 end if;
 if p_active and exists(select 1 from iam.memberships where user_id=p_user_id) then
   raise exception 'subowner_cannot_be_a_company_member' using errcode='23514';
 end if;
 select operator_role,active into v_role,v_active from iam.platform_operators where user_id=p_user_id for update;
 if p_active then
   if found and v_role<>'subowner' then raise exception 'owner_role_is_immutable' using errcode='42501'; end if;
   if found and v_active then return; end if;
   if found then
     update iam.platform_operators set active=true,deactivated_at=null where user_id=p_user_id;
     v_action:='platform.subowner.reactivated';
   else
     insert into iam.platform_operators(user_id,operator_role,created_by) values(p_user_id,'subowner',auth.uid());
     v_action:='platform.subowner.created';
   end if;
 else
   if p_user_id=auth.uid() then raise exception 'owner_cannot_deactivate_self' using errcode='42501'; end if;
   if not found or v_role<>'subowner' then raise exception 'subowner_not_found' using errcode='22023'; end if;
   if not v_active then raise exception 'subowner_already_inactive' using errcode='22023'; end if;
   update iam.platform_operators set active=false,deactivated_at=now() where user_id=p_user_id;
   v_action:='platform.subowner.deactivated';
 end if;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
 values(null,auth.uid(),'platform',v_action,'platform_operator',p_user_id,jsonb_build_object('active',p_active));
end $$;

-- Prevent scope rows from being attached to inactive role assignments. Once a
-- scope binding is revoked, its identifiers and lifecycle cannot be rewritten.
create or replace function private.validate_membership_role_scope() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_assignment iam.membership_roles%rowtype; v_scope text; v_member_status text;
begin
 if tg_op='UPDATE' then return new; end if;
 select * into v_assignment from iam.membership_roles mr
  where mr.tenant_id=new.tenant_id and mr.id=new.membership_role_id;
 if not found or v_assignment.revoked_at is not null or v_assignment.starts_at>now()
   or (v_assignment.ends_at is not null and now()>=v_assignment.ends_at) then
   raise exception 'active role assignment required for scope binding' using errcode='23514';
 end if;
 select m.status into v_member_status from iam.memberships m
  where m.tenant_id=v_assignment.tenant_id and m.id=v_assignment.membership_id;
 if v_member_status is distinct from 'active' then
   raise exception 'active membership required for scope binding' using errcode='23514';
 end if;
 v_scope:=case when tg_table_name='membership_role_sites' then 'site' else 'org_unit' end;
 if not exists(select 1 from iam.role_permissions rp where rp.role_id=v_assignment.role_id
   and rp.active and rp.scope_kind=v_scope) then
   raise exception 'role has no permission for this scope kind' using errcode='23514';
 end if;
 return new;
end $$;

create or replace function private.guard_membership_role_scope_lifecycle() returns trigger
language plpgsql set search_path='' as $$
begin
 if (to_jsonb(new)-array['revoked_at','revoked_by','revoke_reason']) is distinct from
    (to_jsonb(old)-array['revoked_at','revoked_by','revoke_reason']) then
   raise exception 'role scope binding identity and validity are immutable' using errcode='23514';
 end if;
 if old.revoked_at is not null then
   raise exception 'revoked role scope binding is immutable' using errcode='23514';
 end if;
 if new.revoked_at is null and (new.revoked_by is distinct from old.revoked_by or new.revoke_reason is distinct from old.revoke_reason) then
   raise exception 'role scope revocation metadata requires revocation' using errcode='23514';
 end if;
 return new;
end $$;
create trigger membership_role_site_scope_lifecycle before update on iam.membership_role_sites
 for each row execute function private.guard_membership_role_scope_lifecycle();
create trigger membership_role_org_scope_lifecycle before update on iam.membership_role_org_units
 for each row execute function private.guard_membership_role_scope_lifecycle();

create or replace function private.guard_entitlement_grant_lifecycle() returns trigger
language plpgsql set search_path='' as $$
begin
 if (to_jsonb(new)-array['status','revoked_at','revoked_by','revoke_reason']) is distinct from
    (to_jsonb(old)-array['status','revoked_at','revoked_by','revoke_reason']) then
   raise exception 'entitlement grant terms are immutable' using errcode='23514';
 end if;
 if old.revoked_at is not null then
   raise exception 'revoked entitlement grants are immutable' using errcode='23514';
 end if;
 if new.revoked_at is null and (new.revoked_by is distinct from old.revoked_by or new.revoke_reason is distinct from old.revoke_reason) then
   raise exception 'grant revocation metadata requires revocation' using errcode='23514';
 end if;
 return new;
end $$;
create trigger entitlement_grant_lifecycle_guard before update on core.entitlement_grants
 for each row execute function private.guard_entitlement_grant_lifecycle();

-- Any inactive-to-active membership transition resets prior functional/direct
-- access before it can authorize a new session. Rows remain for audit/history.
create or replace function private.reset_membership_authorizations_on_reactivation() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_actor uuid:=coalesce(auth.uid(),new.user_id); v_reason text:='Reset on membership reactivation';
begin
 if old.status is distinct from 'active' and new.status='active' then
   update iam.membership_roles set revoked_at=now(),revoked_by=v_actor,revoke_reason=v_reason
    where tenant_id=new.tenant_id and membership_id=new.id and revoked_at is null;
   update iam.membership_role_sites set revoked_at=now(),revoked_by=v_actor,revoke_reason=v_reason
    where tenant_id=new.tenant_id and membership_role_id in
      (select id from iam.membership_roles where tenant_id=new.tenant_id and membership_id=new.id)
      and revoked_at is null;
   update iam.membership_role_org_units set revoked_at=now(),revoked_by=v_actor,revoke_reason=v_reason
    where tenant_id=new.tenant_id and membership_role_id in
      (select id from iam.membership_roles where tenant_id=new.tenant_id and membership_id=new.id)
      and revoked_at is null;
   update iam.member_permissions set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
   update iam.site_access set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
   update iam.org_unit_access set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
   update iam.task_assignments set active=false where tenant_id=new.tenant_id and membership_id=new.id and active;
 end if;
 return new;
end $$;
create trigger membership_reactivation_access_reset after update of status on iam.memberships
 for each row execute function private.reset_membership_authorizations_on_reactivation();

-- Invitation creation is serialized by tenant/email. Acceptance still locks the
-- invitation row and serializes competing consumers on that row.
create or replace function api.create_invitation(p_tenant_id uuid,p_email text,p_level text,p_actor_user_id uuid,
 p_ttl interval default interval '7 days')
returns table(invitation_id uuid,token text) language plpgsql security definer set search_path='' as $$
declare v_token text:=encode(extensions.gen_random_bytes(32),'hex'); v_id uuid; v_email text:=lower(btrim(p_email));
begin
 if not exists(select 1 from iam.memberships m join core.tenants t on t.id=m.tenant_id
    where m.tenant_id=p_tenant_id and m.user_id=p_actor_user_id and m.member_role='company_superadmin'
      and m.status='active' and t.status='active')
   or p_level not in ('company_admin','employee') or v_email is null or length(v_email)<3 or length(v_email)>254
   or p_ttl is null or p_ttl<=interval '0' or p_ttl>interval '30 days' then
   raise exception 'invitation_not_allowed' using errcode='42501';
 end if;
 perform pg_advisory_xact_lock(hashtextextended('sentriq-invitation:'||p_tenant_id::text||':'||v_email,0));
 if exists(select 1 from iam.memberships m where m.tenant_id=p_tenant_id and m.email=v_email
    and m.status='active') then
   raise exception 'active_membership_already_exists' using errcode='23505';
 end if;
 update iam.invitations set revoked_at=now(),revoked_by=p_actor_user_id,revoke_reason='Expired before reinvitation'
  where tenant_id=p_tenant_id and email=v_email and accepted_at is null and revoked_at is null and expires_at<=now();
 if exists(select 1 from iam.invitations where tenant_id=p_tenant_id and email=v_email
    and accepted_at is null and revoked_at is null) then
   raise exception 'invitation_already_pending' using errcode='23505';
 end if;
 insert into iam.invitations(tenant_id,email,token_hash,intended_level,invited_by,expires_at)
 values(p_tenant_id,v_email,extensions.digest(v_token,'sha256'),p_level,p_actor_user_id,now()+p_ttl)
 returning id into v_id;
 return query select v_id,v_token;
end $$;

create or replace function api.accept_invitation(p_token text,p_auth_user_id uuid)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_inv iam.invitations%rowtype; v_email text; v_membership uuid;
begin
 if p_token is null or length(p_token) not between 32 and 256 or p_auth_user_id is null then
   raise exception 'invitation_invalid_or_expired' using errcode='22023';
 end if;
 select lower(btrim(email)) into v_email from auth.users
  where id=p_auth_user_id and email_confirmed_at is not null;
 if v_email is null or v_email='' then raise exception 'verified_auth_email_required' using errcode='42501'; end if;
 select * into v_inv from iam.invitations where token_hash=extensions.digest(p_token,'sha256') for update;
 if not found or v_inv.accepted_at is not null or v_inv.revoked_at is not null
   or now()>=v_inv.expires_at or v_inv.email<>v_email then
   raise exception 'invitation_invalid_or_expired' using errcode='22023';
 end if;
 if not exists(select 1 from auth.users u where u.id=p_auth_user_id and lower(u.email)=v_email
   and email_confirmed_at is not null) then
   raise exception 'auth_email_mismatch' using errcode='42501';
 end if;
 if exists(select 1 from iam.memberships m where m.tenant_id=v_inv.tenant_id and m.email=v_email
   and m.user_id<>p_auth_user_id) then
   raise exception 'membership_email_belongs_to_another_user' using errcode='23505';
 end if;
 insert into iam.memberships(tenant_id,user_id,member_role,status,email)
 values(v_inv.tenant_id,p_auth_user_id,v_inv.intended_level,'active',v_email)
 on conflict(tenant_id,user_id) do update set member_role=excluded.member_role,status='active',email=excluded.email,updated_at=now()
   where iam.memberships.status in ('invited','ended','suspended')
 returning id into v_membership;
 if v_membership is null then raise exception 'membership_already_active' using errcode='23505'; end if;
 insert into audit.events(tenant_id,actor_user_id,actor_membership_id,scope_kind,action_key,record_type,record_id,summary)
 values(v_inv.tenant_id,p_auth_user_id,v_membership,'tenant','iam.invitation.accepted','iam.memberships',v_membership,
   jsonb_build_object('invitation_id',v_inv.id,'management_level',v_inv.intended_level));
 update iam.invitations set accepted_at=now(),accepted_by=p_auth_user_id where id=v_inv.id;
 return v_membership;
end $$;

revoke all on function private.has_module_entitlement(uuid,text),private.has_feature_entitlement(uuid,uuid,text),
 private.validate_membership_role_scope(),private.guard_membership_role_scope_lifecycle(),
 private.reset_membership_authorizations_on_reactivation(),private.guard_entitlement_grant_lifecycle() from public,anon,authenticated;
revoke all on function api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb),
 api.invoice_usage_event(uuid,uuid,text),api.create_invitation(uuid,text,text,uuid,interval),
 api.accept_invitation(text,uuid) from public,anon,authenticated;
grant execute on function api.record_feature_usage(uuid,uuid,text,text,numeric,text,jsonb),
 api.invoice_usage_event(uuid,uuid,text) to service_role;
grant execute on function api.create_invitation(uuid,text,text,uuid,interval),
 api.accept_invitation(text,uuid) to service_role;
revoke all on function api.update_subscription_status(uuid,text),
 api.create_subscription(uuid,uuid,timestamptz,timestamptz,char,jsonb),
 api.issue_entitlement_grant(uuid,text,text,uuid,timestamptz,timestamptz,text,text,char,bigint,numeric),
 api.set_entitlement_grant_status(uuid,text,text),api.manage_subowner(uuid,boolean) from public,anon;
grant execute on function api.update_subscription_status(uuid,text),
 api.create_subscription(uuid,uuid,timestamptz,timestamptz,char,jsonb),
 api.issue_entitlement_grant(uuid,text,text,uuid,timestamptz,timestamptz,text,text,char,bigint,numeric),
 api.set_entitlement_grant_status(uuid,text,text),api.manage_subowner(uuid,boolean) to authenticated;

commit;
