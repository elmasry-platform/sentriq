create extension if not exists pgtap with schema extensions;
begin;
select extensions.plan(26);

insert into auth.users(id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at) values
 ('00000000-0000-0000-0000-000000000101','authenticated','authenticated','phase1-owner@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000102','authenticated','authenticated','phase1-admin@example.test','',now(),'{}','{}',now(),now()),
 ('00000000-0000-0000-0000-000000000103','authenticated','authenticated','phase1-operator@example.test','',now(),'{}','{}',now(),now());
select private.bootstrap_platform_owner('00000000-0000-0000-0000-000000000101');
insert into iam.platform_operators(user_id,operator_role,created_by)
 values('00000000-0000-0000-0000-000000000103','subowner','00000000-0000-0000-0000-000000000101');
insert into core.tenants(id,name,created_by) values
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','Phase 1 A','00000000-0000-0000-0000-000000000101'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbb01','Phase 1 B','00000000-0000-0000-0000-000000000101');
insert into iam.memberships(id,tenant_id,user_id,member_role,status,email) values
 ('10000000-0000-0000-0000-00000000a101','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','00000000-0000-0000-0000-000000000102','company_superadmin','active','phase1-admin@example.test');
insert into core.tenant_entitlements(tenant_id,module_key,status,changed_by)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','hse','active','00000000-0000-0000-0000-000000000101');
insert into core.entitlement_grants(tenant_id,module_key,starts_at,expires_at,granted_by,reason,billing_treatment,source_kind,legacy_entitlement_id)
select tenant_id,module_key,created_at,'infinity'::timestamptz,changed_by,'Phase 1 test','complimentary','legacy_backfill',id
 from core.tenant_entitlements where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101';
insert into core.org_units(id,tenant_id,name) values
 ('20000000-0000-0000-0000-00000000a101','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','A Unit'),
 ('20000000-0000-0000-0000-00000000b101','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbb01','B Unit');
insert into core.sites(id,tenant_id,org_unit_id,name,code) values
 ('30000000-0000-0000-0000-00000000a101','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','20000000-0000-0000-0000-00000000a101','A Site','A101'),
 ('30000000-0000-0000-0000-00000000b101','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbb01',null,'B Site','B101');
insert into hse.people(id,tenant_id,display_name,person_kind,created_by) values
 ('40000000-0000-0000-0000-00000000a101','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','Independent person','employee','00000000-0000-0000-0000-000000000101'),
 ('40000000-0000-0000-0000-00000000b101','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbb01','Separate tenant person','employee','00000000-0000-0000-0000-000000000101');

select extensions.ok((select relrowsecurity and relforcerowsecurity from pg_class where oid='hse.people'::regclass),'People table forces RLS');
select extensions.ok((select relrowsecurity and relforcerowsecurity from pg_class where oid='hse.person_engagements'::regclass),'Engagement table forces RLS');
select extensions.ok(not has_table_privilege('authenticated','hse.people','DELETE') and not has_table_privilege('anon','hse.people','SELECT'),'no browser delete or anonymous read path');
select extensions.ok(exists(select 1 from pg_constraint where conrelid='hse.person_engagements'::regclass and contype='f' and conname like '%person%'),'engagement has same-tenant person foreign key');

select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000102',true);
select set_config('request.jwt.claim.role','authenticated',true);
set local role authenticated;
select extensions.is((select count(*)::integer from hse.people),1,'Company Superadmin sees only company A People');
select extensions.is((select count(*)::integer from hse.people where id='40000000-0000-0000-0000-00000000b101'),0,'cross-tenant person ID is invisible');
select extensions.lives_ok($$update hse.people set membership_id='10000000-0000-0000-0000-00000000a101' where id='40000000-0000-0000-0000-00000000a101'$$,'same-tenant person-membership link is allowed under its explicit Superadmin capability');
select extensions.lives_ok($$insert into hse.person_engagements(id,tenant_id,person_id,engagement_type,site_id,org_unit_id,created_by) values('50000000-0000-0000-0000-00000000a101','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','40000000-0000-0000-0000-00000000a101','employee','30000000-0000-0000-0000-00000000a101','20000000-0000-0000-0000-00000000a101','00000000-0000-0000-0000-000000000102')$$,'valid site and org engagement is accepted');
select extensions.throws_ok($$insert into hse.person_engagements(tenant_id,person_id,engagement_type,created_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','40000000-0000-0000-0000-00000000b101','employee','00000000-0000-0000-0000-000000000102')$$,'23503',null,'cross-tenant person relationship is rejected by composite FK');
select extensions.throws_ok($$insert into hse.person_engagements(tenant_id,person_id,engagement_type,site_id,org_unit_id,created_by) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','40000000-0000-0000-0000-00000000a101','employee','30000000-0000-0000-0000-00000000a101','20000000-0000-0000-0000-00000000b101','00000000-0000-0000-0000-000000000102')$$,'23514',null,'D-20 rejects an engagement org that differs from its Site org');
select extensions.is((select count(*)::integer from hse.person_engagement_events where engagement_id='50000000-0000-0000-0000-00000000a101'),1,'engagement creation appends one lifecycle event');
select extensions.throws_ok($$update hse.person_engagement_events set event_type='updated' where engagement_id='50000000-0000-0000-0000-00000000a101'$$,'42501',null,'engagement event history is append-only');
select extensions.throws_ok($$update core.sites set org_unit_id=null where id='30000000-0000-0000-0000-00000000a101'$$,'23514',null,'D-20 guard rejects conflicting reassignment by a company actor');
reset role;
select extensions.throws_ok($$update core.sites set org_unit_id=null where id='30000000-0000-0000-0000-00000000a101'$$,'23514',null,'D-20 rejects Site reassignment conflicting with active engagement');
insert into iam.member_permission_decisions(tenant_id,membership_id,permission_key,decision,scope_kind,
 granted_by,reason)
 values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','10000000-0000-0000-0000-00000000a101','view_all','deny','tenant',
   '00000000-0000-0000-0000-000000000101','Phase 1 deny precedence test');
set local role authenticated;
select extensions.is((select count(*)::integer from hse.people),0,'explicit direct deny overrides Superadmin capability defaults');
reset role;
update core.tenants set status='suspended' where id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101';
select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000102',true);
set local role authenticated;
select extensions.is((select count(*)::integer from hse.person_engagements),0,'suspended tenant denies Phase 1 engagement access');
reset role;
update core.tenants set status='active' where id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101';

select set_config('request.jwt.claim.sub','00000000-0000-0000-0000-000000000103',true);
set local role authenticated;
select extensions.is((select count(*)::integer from hse.people),0,'Platform Subowner has no implicit company People access');
select extensions.is((select count(*)::integer from core.sites where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101'),0,'Platform Subowner has no implicit Phase 1 Site access');
select extensions.is((select count(*)::integer from core.org_units where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101'),0,'Platform Subowner has no implicit Phase 1 org-unit access');
select extensions.ok(not private.can_access_hse('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','hse.forms.read',null,false,null,null),'Platform Subowner cannot use the legacy HSE helper even when the company has HSE access');
select extensions.is((select count(*)::integer from iam.memberships where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101'),0,'Platform Subowner cannot read company membership identities');
select extensions.is((select count(*)::integer from iam.roles where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101'),0,'Platform Subowner cannot read tenant functional roles');
select extensions.is((select count(*)::integer from audit.events where tenant_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101'),0,'Platform Subowner cannot read company audit events');
select extensions.ok(not private.can_access_core('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','core.structure.manage','30000000-0000-0000-0000-00000000a101',true),'Platform Subowner cannot use the legacy core access helper');
select extensions.throws_ok($$insert into core.sites(tenant_id,name,code) values('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaa101','Forbidden site','FORBID')$$,'42501',null,'Platform Subowner cannot create a company Site without company membership');
reset role;
select extensions.throws_ok($$update core.org_units set parent_id='20000000-0000-0000-0000-00000000a101' where id='20000000-0000-0000-0000-00000000a101'$$,'23514',null,'organizational hierarchy rejects self cycles');

select * from extensions.finish();
rollback;
