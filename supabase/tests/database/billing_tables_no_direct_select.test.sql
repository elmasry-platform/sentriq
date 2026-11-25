-- 047: authenticated has no direct SELECT on core.invoices / core.payments; the audited definer path still works.
begin;
grant usage on schema extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select extensions.plan(16);
insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-0000000047c1','authenticated','authenticated','bt-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-0000000047c2','authenticated','authenticated','bt-member@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-0000000047c1');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000047c1',true);
select set_config('request.jwt.claim.role','authenticated',true);
insert into core.tenants(id,name,created_by) values ('47a00000-0000-0000-0000-00000000000a','Billing A','00000000-0000-0000-0000-0000000047c1');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('47200000-0000-0000-0000-000000000001','47a00000-0000-0000-0000-00000000000a','00000000-0000-0000-0000-0000000047c2','company_superadmin','active','bt-member@example.test');
set local session_replication_role = replica;
insert into core.invoices(id,tenant_id,invoice_number,status,currency,period_start,period_end) values ('47100000-0000-0000-0000-000000000001','47a00000-0000-0000-0000-00000000000a','INV-47-1','issued','USD',now()-interval '30 days',now());
insert into core.payments(tenant_id,invoice_id,provider,provider_reference,status,amount_minor,currency) values ('47a00000-0000-0000-0000-00000000000a','47100000-0000-0000-0000-000000000001','test','bt-ref-1','pending',0,'USD');
set local session_replication_role = origin;
-- Catalog: the privilege is gone.
select extensions.ok(not has_table_privilege('authenticated','core.invoices','select'),'R01 authenticated has no SELECT on core.invoices');
select extensions.ok(not has_table_privilege('authenticated','core.payments','select'),'R02 authenticated has no SELECT on core.payments');
select extensions.ok(not has_any_column_privilege('authenticated','core.invoices','select') and not has_any_column_privilege('authenticated','core.payments','select'),'R03 no column-level SELECT either, so no column grant can bypass the revoke');
select extensions.ok(not has_table_privilege('anon','core.invoices','select') and not has_table_privilege('anon','core.payments','select'),'R04 anon has no SELECT on either table');
select extensions.ok(not has_table_privilege('authenticated','core.invoices','insert,update,delete') and not has_table_privilege('authenticated','core.payments','insert,update,delete'),'R05 authenticated still has no write privilege (unchanged)');
-- Runtime: the denial is a privilege error, not an empty result.
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000047c2',true);
set local role authenticated;
select extensions.throws_ok($$select count(*) from core.invoices$$,'42501','permission denied for table invoices','R06 a company superadmin cannot select core.invoices');
select extensions.throws_ok($$select count(*) from core.payments$$,'42501','permission denied for table payments','R07 a company superadmin cannot select core.payments');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000047c1',true);
select extensions.throws_ok($$select count(*) from core.invoices$$,'42501','permission denied for table invoices','R08 a platform operator cannot select core.invoices directly');
select extensions.throws_ok($$select count(*) from core.payments$$,'42501','permission denied for table payments','R09 a platform operator cannot select core.payments directly');
-- The app path still works: audited definer read.
select extensions.is((select jsonb_array_length(api.platform_read_company('47a00000-0000-0000-0000-00000000000a','core.invoices',10,0)->'rows')),1,'R10 positive control: the operator reads the invoice through api.platform_read_company');
select extensions.is((select jsonb_array_length(api.platform_read_company('47a00000-0000-0000-0000-00000000000a','core.payments',10,0)->'rows')),1,'R11 positive control: the operator reads the payment through api.platform_read_company');
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-0000000047c2',true);
select extensions.throws_ok($$select api.platform_read_company('47a00000-0000-0000-0000-00000000000a','core.invoices',10,0)$$,'42501','platform_read_not_authorized','R12 a non-operator is still refused by the audited read function');
reset role;
-- Catalog: the paths that touch these tables stay owner-level.
select extensions.is((select count(*)::int from pg_proc p where p.pronamespace in ('api'::regnamespace) and p.proname in ('platform_read_company','invoice_usage_event','record_feature_usage') and p.prosecdef and pg_get_userbyid(p.proowner)='postgres'),3,'R13 the three functions that read or write these tables are SECURITY DEFINER and owned by postgres');
select extensions.ok(has_table_privilege('postgres','core.invoices','select') and has_table_privilege('postgres','core.payments','select'),'R14 the owner keeps SELECT');
select extensions.ok(has_table_privilege('authenticated','core.subscriptions','select') and has_table_privilege('authenticated','core.invoice_items','select') and has_table_privilege('authenticated','iam.memberships','select'),'R15 scope control: other tables keep their SELECT grant (047 only touches invoices and payments)');
select extensions.is((select count(*)::int from pg_policy p where p.polrelid in ('core.invoices'::regclass,'core.payments'::regclass)),4,'R16 RLS policies are untouched (two per table: operator read plus restrictive operator boundary)');
select * from extensions.finish();
rollback;
