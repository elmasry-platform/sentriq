-- Complete RLS coverage for historical role classification review.
begin;
alter table iam.phase1_role_family_review enable row level security;
alter table iam.phase1_role_family_review force row level security;
revoke all on iam.phase1_role_family_review from public,anon,authenticated,service_role;
grant select on iam.phase1_role_family_review to authenticated;
create policy family_review_company_read on iam.phase1_role_family_review for select to authenticated
 using(private.can_manage_tenant(tenant_id));
create trigger family_review_tenant_immutable before update of tenant_id on iam.phase1_role_family_review
 for each row execute function private.guard_tenant_id_immutable();

-- All role scope rows must remain within the captured incoming envelope, not
-- merely some other envelope that happens to be available to the same actor.
create or replace function private.validate_assignment_source_scope() returns trigger
language plpgsql security definer set search_path='' as $$
declare a iam.membership_roles%rowtype;d iam.delegation_envelopes%rowtype;v_scope uuid;
begin
 select * into a from iam.membership_roles where tenant_id=new.tenant_id and id=new.membership_role_id;
 if a.source_delegation_id is null then return new;end if;
 select * into d from iam.delegation_envelopes where tenant_id=new.tenant_id and id=a.source_delegation_id;
 if not private.decision_source_valid(d.id,d.tenant_id) then raise exception 'role_source_expired' using errcode='42501';end if;
 if d.level in ('tenant','employees_default') then return new;end if;
 if tg_table_name='membership_role_sites' and (d.level<>'site' or d.site_id<>new.site_id) then
  raise exception 'role_site_outside_exact_source' using errcode='42501';end if;
 if tg_table_name='membership_role_org_units' and (d.level<>'org_unit' or d.org_unit_id<>new.org_unit_id) then
  raise exception 'role_org_outside_exact_source' using errcode='42501';end if;
 return new;
end $$;
create trigger exact_role_site_source before insert or update on iam.membership_role_sites
 for each row execute function private.validate_assignment_source_scope();
create trigger exact_role_org_source before insert or update on iam.membership_role_org_units
 for each row execute function private.validate_assignment_source_scope();
revoke all on function private.validate_assignment_source_scope() from public,anon,authenticated,service_role;
commit;
