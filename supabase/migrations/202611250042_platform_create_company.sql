-- 042: add a company without naming its first user.
-- api.create_tenant needs an existing Superadmin user id, so an operator cannot add a company and then
-- invite its Superadmin by email. This adds api.platform_create_company(name, industry): it only creates
-- the company (no member, no module). The Superadmin is then invited with api.platform_create_invitation.
-- Power: company.create (Owner always; Sub-owner only if the Owner has not withdrawn it). Audited.
begin;

create or replace function api.platform_create_company(p_name text, p_industry_label text default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid; v_name text:=btrim(coalesce(p_name,''));
begin
 if auth.uid() is null or not private.platform_permission_allowed('company.create') then
  raise exception 'insufficient_privilege' using errcode='42501'; end if;
 if length(v_name) < 2 or length(v_name) > 200 then raise exception 'company_name_invalid' using errcode='22023'; end if;
 if exists(select 1 from core.tenants t where lower(t.name)=lower(v_name)) then
  raise exception 'company_name_taken' using errcode='23505'; end if;
 insert into core.tenants(name,industry_label,created_by) values(v_name,nullif(btrim(coalesce(p_industry_label,'')),''),auth.uid())
  returning id into v_id;
 insert into audit.events(tenant_id,actor_user_id,scope_kind,action_key,record_type,record_id,summary)
  values(v_id,auth.uid(),'platform','company.create','tenant',v_id,jsonb_build_object('name',v_name,'first_member',false));
 return v_id;
end $$;

revoke all on function api.platform_create_company(text,text) from public,anon;
grant execute on function api.platform_create_company(text,text) to authenticated;

commit;
