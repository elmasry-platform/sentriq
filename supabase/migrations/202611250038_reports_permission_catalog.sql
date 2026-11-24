-- Reports becomes its own permission: analytics that can be generated
-- automatically or on demand by an employee. Standalone catalog key, not a
-- mapping to findings/audit reads. Default state follows the role (no role
-- grants it yet, so it starts denied until a superadmin allows it or a role
-- version includes it). supported_actions includes write for future
-- "generate report" flows; scope kinds mirror the other hse keys.

insert into iam.permission_catalog(permission_key,module_key,label,description,enabled,feature_key,supported_actions,supported_scope_kinds,requires_reason,is_sensitive)
values('hse.reports.read','hse','Reports','Generate and view analytics reports; automatic or employee-initiated.',true,null,
       '{read,write}','{tenant,site,org_unit,assigned_task}',false,false)
on conflict(permission_key) do nothing;
