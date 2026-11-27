-- Rollback of 057: restore the previous function bodies, then drop the switch objects.
CREATE OR REPLACE FUNCTION private.is_platform_operator()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active)
$function$;

CREATE OR REPLACE FUNCTION private.is_platform_owner()
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from iam.platform_operators p where p.user_id = auth.uid() and p.active and p.operator_role = 'owner')
$function$;

CREATE OR REPLACE FUNCTION private.platform_permission_allowed(p_key text, p_actor uuid DEFAULT NULL::uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
 select exists(select 1 from iam.platform_operators o where o.user_id=coalesce(p_actor,private.request_actor_id()) and o.active
  and (o.operator_role='owner'
   or (o.operator_role='subowner' and not exists(select 1 from iam.platform_permission_grants g
        where g.user_id=o.user_id and g.permission_key=p_key and not g.granted))))
$function$;

CREATE OR REPLACE FUNCTION private.operator_decision_actor()
 RETURNS uuid
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v uuid:=nullif(current_setting('sentriq.operator_decision_actor',true),'')::uuid;
begin
 if v is not null and v=auth.uid() and exists(select 1 from iam.platform_operators o where o.user_id=v and o.active)
    and private.platform_permission_allowed('member.permissions',v) then return v; end if;
 return null;
end $function$;

CREATE OR REPLACE FUNCTION api.my_platform_permissions()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_rows jsonb; v_role text;
begin
 select po.operator_role into v_role
   from iam.platform_operators po
  where po.user_id=private.request_actor_id() and po.active;
 if v_role is null then raise exception 'platform_operator_required' using errcode='42501'; end if;
 if v_role = 'owner' then
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',true) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 else
   select coalesce(jsonb_agg(jsonb_build_object('permission_key',c.permission_key,'granted',private.platform_permission_allowed(c.permission_key,private.request_actor_id())) order by c.permission_key),'[]'::jsonb)
     into v_rows from iam.platform_permission_catalog c;
 end if;
 return jsonb_build_object('rows',v_rows);
end $function$;


drop function if exists private.set_platform_aal2_required(boolean, text);
drop function if exists private.platform_aal_ok();
drop table if exists iam.platform_security_settings;
drop function if exists private.platform_security_settings_guard();
drop function if exists private.platform_security_settings_audit();
